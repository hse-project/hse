from bokeh.plotting import figure, output_file, save, gridplot
from bokeh.layouts import layout, gridplot
from bokeh.models import Div, ColumnDataSource
import pandas as pd
import os, re
from .tree_shape import TreeShape
from .util import Util
import yaml

GET_COLOR = "chocolate"
CURSOR_COLOR = "darkcyan"


class Crossover:
    def __init__(self, height=500, width=500):
        self.height = height
        self.width = width

    def __get_blen_list(self, dirpath):
        flist = os.listdir(dirpath)
        c = re.compile(r"rr_cursor_(\d+)_out")
        lst = []
        for f in flist:
            x = c.search(f)
            if x:
                lst.append(int(x.group(1)))

        lst = sorted(lst)
        return lst

    def df_for_nkeys(self, nkey_dir, c_avg_nkvset, g_avg_nkvset):
        bl_list = self.__get_blen_list(nkey_dir)
        out = []
        for bl in bl_list:
            # Values per second
            df = pd.read_csv("{}/rr_cursor_{}_out.log".format(nkey_dir, bl))
            cm = df["rRate"].mean()
            df = pd.read_csv("{}/rr_get_{}_out.log".format(nkey_dir, bl))
            gm = df["rRate"].mean()

            # Latency
            df = pd.read_csv(
                "{}/rr_cursor_{}_lat_out.log".format(nkey_dir, bl),
                index_col=False,
                names=["latency"],
            )
            df["latencyNormalized"] = df["latency"] / bl
            cLatMean = df["latencyNormalized"].mean()
            cLatStd = df["latencyNormalized"].std() / cLatMean
            cLatMeanKvset = cLatMean / c_avg_nkvset

            df = pd.read_csv(
                "{}/rr_get_{}_lat_out.log".format(nkey_dir, bl),
                index_col=False,
                names=["latency"],
            )
            df["latencyNormalized"] = df["latency"] / bl
            gLatMean = df["latencyNormalized"].mean()
            gLatStd = df["latencyNormalized"].std() / gLatMean
            gLatMeanKvset = gLatMean / g_avg_nkvset

            out.append(
                [
                    bl,
                    cm,
                    gm,
                    cLatMean,
                    gLatMean,
                    cLatStd,
                    gLatStd,
                    cLatMeanKvset,
                    gLatMeanKvset,
                ]
            )

        df = pd.DataFrame(
            out,
            columns=[
                "BurstLen",
                "Cursor",
                "Get",
                "CursorLatMean",
                "GetLatMean",
                "CursorLatStd",
                "GetLatStd",
                "CursorLatMeanKvset",
                "GetLatMeanKvset",
            ],
        )
        return df

    def __plot_one(
        self,
        width=0,
        height=0,
        cursor_col="Cursor",
        get_col="Get",
        y_label="",
        title=None,
        source=None,
        x_range=None,
        legend_location="top_right",
    ):
        if height == 0:
            height = self.height

        if width == 0:
            width = self.width

        TOOLTIPS = [("Data", "($x,$y)")]
        if x_range:
            p = figure(
                title=title,
                tooltips=TOOLTIPS,
                width=width,
                height=height,
                toolbar_location="right",
                x_range=x_range,
            )
        else:
            p = figure(
                title=title,
                tooltips=TOOLTIPS,
                width=width,
                height=height,
                toolbar_location="right",
            )

        p.line(
            "BurstLen",
            cursor_col,
            legend_label="Cursor",
            line_color=CURSOR_COLOR,
            source=source,
        )
        p.circle(
            "BurstLen",
            cursor_col,
            legend_label="Cursor",
            fill_color=CURSOR_COLOR,
            line_color=CURSOR_COLOR,
            size=3,
            source=source,
        )

        p.line(
            "BurstLen", get_col, legend_label="Get", line_color=GET_COLOR, source=source
        )
        p.circle(
            "BurstLen",
            get_col,
            legend_label="Get",
            fill_color=GET_COLOR,
            line_color=GET_COLOR,
            size=3,
            source=source,
        )

        # Axes
        p.xaxis.axis_label = "Burstlen"
        p.yaxis.axis_label = y_label

        # Setup legend
        p.legend.location = legend_location
        p.legend.glyph_height = 10
        p.legend.orientation = "vertical"
        p.legend.label_height = 5

        p.legend.label_text_font_size = "12px"
        return p

    def plot_ops(
        self, source=None, title=None, x_range=None, legend_location="top_right"
    ):
        return self.__plot_one(
            source=source,
            x_range=x_range,
            legend_location=legend_location,
            cursor_col="Cursor",
            get_col="Get",
            y_label="Values/sec",
            title=title,
        )

    def plot_lat_mean(
        self, source=None, title=None, x_range=None, legend_location="top_right"
    ):
        return self.__plot_one(
            width=int(self.width / 3),
            source=source,
            x_range=x_range,
            legend_location=legend_location,
            cursor_col="CursorLatMean",
            get_col="GetLatMean",
            y_label="ns",
            title=title,
        )

    def plot_lat_std(
        self, source=None, title=None, x_range=None, legend_location="top_right"
    ):
        return self.__plot_one(
            width=int(self.width / 3),
            source=source,
            x_range=x_range,
            legend_location=legend_location,
            cursor_col="CursorLatStd",
            get_col="GetLatStd",
            y_label="",
            title=title,
        )

    def plot_lat_mean_kvset(
        self, source=None, title=None, x_range=None, legend_location="top_right"
    ):
        return self.__plot_one(
            width=int(self.width / 3),
            source=source,
            x_range=x_range,
            legend_location=legend_location,
            cursor_col="CursorLatMeanKvset",
            get_col="GetLatMeanKvset",
            y_label="ns",
            title=title,
        )

    def plot(self, df):
        source = ColumnDataSource(df)
        h = self.height
        self.height = int(self.height / 2)

        ValPerSec = self.plot_ops(
            source=source,
            title="Values retrieved per second",
            legend_location="top_left",
        )
        latMean = self.plot_lat_mean(
            source=source,
            title="Latency Mean",
            x_range=ValPerSec.x_range,
            legend_location="top_right",
        )
        latMeanKvset = self.plot_lat_mean_kvset(
            source=source,
            title="Latency Mean norm. to nKvsets",
            x_range=ValPerSec.x_range,
            legend_location="top_right",
        )
        latStd = self.plot_lat_std(
            source=source,
            title="Latency StdDev",
            x_range=ValPerSec.x_range,
            legend_location="top_left",
        )

        self.height = h
        return layout([ValPerSec, [latMean, latMeanKvset, latStd]])
