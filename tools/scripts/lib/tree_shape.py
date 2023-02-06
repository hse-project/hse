# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

"""
References:
    https://docs.bokeh.org/en/latest/docs/user_guide/graph.html#layout-providers
    https://docs.bokeh.org/en/latest/docs/user_guide/tools.html#custom-tooltip
    https://docs.bokeh.org/en/latest/docs/user_guide/interaction/widgets.html?highlight=sliders#tabs
    https://stackoverflow.com/questions/55492898/slider-based-on-networkx-node-attribute-value-with-bokeh
"""

import math
import yaml
import pandas as pd
from bokeh.plotting import output_file, figure, save, gridplot
from bokeh.layouts import layout
from bokeh.models import (
    Ellipse,
    MultiLine,
    GraphRenderer,
    StaticLayoutProvider,
    Slider,
    CustomJS,
)
from bokeh.palettes import Spectral8

from .util import Util


class TreeNode:
    def __init__(self, level, offset, node_info):
        self.level = level
        self.offset = offset
        self.children = []
        self.node_info = node_info

    def add_child(self, child):
        self.children.append(child)

    def sum_in_subtree(self, param_name="nkvsets"):
        def traverse_recursive(tn):
            param_sum = 0
            for c in tn.children:
                param_sum += traverse_recursive(c)

            return param_sum + tn.node_info[param_name]

        return traverse_recursive(self)

    def sum_by_path(self, pivot=2, param_name="nkvsets"):
        """
        For point gets set pivot to infinity
        """

        def traverse_recursive(tn, param_sum=0, param_name="nkvsets"):
            if tn.level < pivot:
                """
                If this is a leaf node, we're at
                the end of a path. Return current sum
                and '1' to denote a new path
                """
                if len(tn.children) == 0:
                    return param_sum + tn.node_info[param_name], 1

                # Not a Leaf node...
                sum_tot = 0
                path_cnt_tot = 0

                for c in tn.children:
                    kv_sum, path_cnt = traverse_recursive(
                        c, param_sum + tn.node_info[param_name]
                    )
                    sum_tot += kv_sum
                    path_cnt_tot += path_cnt

                return sum_tot, path_cnt_tot
            else:
                nkv = tn.sum_in_subtree()
                return param_sum + nkv, 1

        return traverse_recursive(tn=self, param_sum=0, param_name=param_name)


class TreeShape:
    def __init__(self, fanout, width=500, height=500):
        self.fanout = int(fanout)
        self.max_dim = 0
        self.max_radius = 0
        self.fig_width = width
        self.fig_height = height
        self.el_size = 1  # Ellipse size

        self.nrd_list = []  # Node renderer list
        self.erd_list = []  # Edge renderer list
        self.graph_layout_list = []  # Stores x,y coordinates associated with each node

        self.util = Util()
        self.graph = GraphRenderer()

    def __get_parent(self, node):
        level = node[0]
        offset = node[1]
        if level == 0:
            return node

        level -= 1
        offset = int(offset / self.fanout)
        return (level, offset)

    def __get_edges(self, nodes):
        start = []
        end = []
        d = {}

        i = 0
        for n in nodes:
            d[n] = i
            i = i + 1

        i = 0
        for n in nodes:
            parent = self.__get_parent(n)
            if parent in d:
                start.append(d[parent])
                end.append(i)
            i = i + 1

        return start, end

    def construct_tree(self, ybuf):
        get_path_list = []
        cursor_path_list = []

        """
          node --> [child1, child2, ... ]
        """
        tree_dict = {}
        nkvsets = 0
        for n in ybuf["nodes"]:
            level = int(n["loc"]["level"])
            offset = int(n["loc"]["offset"])
            nkvsets += n["info"]["nkvsets"]

            tree_dict[(level, offset)] = TreeNode(
                level=level, offset=offset, node_info=n["info"]
            )

        root = None
        for t in sorted(tree_dict, key=lambda s: (s[0], s[1])):
            level = int(t[0])
            offset = int(t[1])
            n = tree_dict[(level, offset)]

            if level > 0:
                parent_level = level - 1
                parent_offset = int(offset / self.fanout)
                p = tree_dict[(parent_level, parent_offset)]
                p.add_child(n)
            else:
                root = n

        return root

    def avg_nkvset(self, ybuf, pivot):
        if ybuf["info"]["open"] == False:
            return 0, 0, 0

        root = self.construct_tree(ybuf)

        tot_nkvset = root.sum_in_subtree(param_name="nkvsets")
        c_sum_nkvsets, c_num_paths = root.sum_by_path(pivot=pivot, param_name="nkvsets")
        g_sum_nkvsets, g_num_paths = root.sum_by_path(pivot=9999, param_name="nkvsets")

        if c_num_paths == 0:
            c_num_paths = 1
        if g_num_paths == 0:
            g_num_paths = 1

        c_avg = int(c_sum_nkvsets / c_num_paths)
        g_avg = int(g_sum_nkvsets / g_num_paths)
        return tot_nkvset, c_avg, g_avg

    def process_yaml(self, ybuf):
        d = {}
        d["nodes"] = []
        d["levels"] = []
        d["offsets"] = []
        d["node_size"] = []
        d["human_node_size"] = []
        d["node_len"] = []
        d["node_nkblks"] = []
        d["node_nvblks"] = []

        if "info" not in ybuf or ybuf["info"]["open"] == False:
            return None

        for n in ybuf["nodes"]:
            d["nodes"].append((n["loc"]["level"], n["loc"]["offset"]))
            d["levels"].append(n["loc"]["level"])
            d["offsets"].append(n["loc"]["offset"])

            sz = n["info"]["klen"] + n["info"]["vlen"]
            d["node_size"].append(sz)
            d["human_node_size"].append(self.util.humanize(sz))

            # For tooltips
            info = n["info"]
            d["node_len"].append(int(info["nkvsets"]))
            d["node_nkblks"].append(int(info["nkblks"]))
            d["node_nvblks"].append(int(info["nvblks"]))

        d["index"] = list(range(len(d["levels"])))

        max_len = max(d["node_size"])

        def size_color(x, max_x):
            if max_x == 0:
                return "white"

            ratio = int(100 * x / max_x)
            if ratio == 0:
                return "white"
            elif ratio < 33:
                return "green"
            elif ratio < 66:
                return "yellow"
            else:
                return "red"

            return "black"

        d["color"] = [size_color(x, max_len) for x in d["node_size"]]

        return d

    def add_tree_data(self, node_renderer_data):
        # Node renderers
        self.nrd_list.append(node_renderer_data)

        # Graph layout (x,y locations of the nodes)
        def theta(l, o):
            return o * 2 * math.pi / (self.fanout ** l)

        def radius(l):
            if l == 0:
                return 0

            cnt = self.fanout ** l
            rad = (cnt * self.el_size) / (2 * math.pi)
            return rad

        d = node_renderer_data
        x = [radius(l) * math.cos(theta(l, o)) for l, o in d["nodes"]]
        y = [radius(l) * math.sin(theta(l, o)) for l, o in d["nodes"]]

        self.graph_layout_list.append(dict(zip(d["index"], zip(x, y))))

        # Edge renderers
        s, e = self.__get_edges(d["nodes"])
        self.erd_list.append(dict(start=s, end=e))

        # Get the max dimensions for x and y axes
        radii = [radius(l) for l in d["levels"]]
        max_radius = max(radii)
        if self.max_radius <= max_radius:
            self.max_radius = max_radius
            self.max_dim = (max_radius + self.el_size) * 1.2

    def create_slider(self):
        last = len(self.nrd_list) - 1
        slider = Slider(
            start=0,
            default_size=self.fig_width,
            end=last,
            value=last,
            step=1,
            title="Tree shape timeline",
        )
        callback = CustomJS(
            args=dict(
                graph=self.graph,
                nrd_list=self.nrd_list,
                erd_list=self.erd_list,
                graph_layout_list=self.graph_layout_list,
            ),
            code="""
            var g = graph
            var tree_nr = cb_obj.value

            // Update to tree_nr-th tree
            g.node_renderer.data_source.data = nrd_list[tree_nr]
            g.edge_renderer.data_source.data = erd_list[tree_nr]
            g.layout_provider.graph_layout = graph_layout_list[tree_nr]
        """,
        )
        slider.js_on_change("value", callback)
        return slider

    def plot_graph(self, title):
        if len(self.nrd_list) == 0:
            return None, None

        last = len(self.nrd_list) - 1
        self.graph.node_renderer.data_source.data = self.nrd_list[last]
        self.graph.edge_renderer.data_source.data = self.erd_list[last]

        TOOLTIPS = [
            ("index", "@index"),
            ("loc", "(@levels, @offsets)"),
            ("size", "@human_node_size"),
            ("nkvsets", "@node_len"),
            ("kblks", "@node_nkblks"),
            ("vblks", "@node_nvblks"),
        ]

        self.graph.node_renderer.glyph = Ellipse(
            height=self.el_size, width=self.el_size, fill_alpha=0.8, fill_color="color"
        )
        self.graph.edge_renderer.glyph = MultiLine(
            line_color="black", line_alpha=0.8, line_width=0.5
        )

        graph_layout = self.graph_layout_list[last]
        self.graph.layout_provider = StaticLayoutProvider(graph_layout=graph_layout)

        plot = figure(
            title=title,
            x_range=(-self.max_dim, self.max_dim),
            y_range=(-self.max_dim, self.max_dim),
            width=self.fig_width,
            height=self.fig_height,
            tools="wheel_zoom,box_zoom,pan,reset,undo",
            tooltips=TOOLTIPS,
            toolbar_location="right",
        )

        plot.ygrid.visible = False
        plot.renderers.append(self.graph)

        # Set up slider
        slider = None
        if len(self.nrd_list) > 1:
            slider = self.create_slider()

        return plot, slider
