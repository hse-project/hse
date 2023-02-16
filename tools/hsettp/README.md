<!--
SPDX-License-Identifier: Apache-2.0 OR MIT

SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
-->

# `hsettp`

This tool allows you to interact with the HSE REST API. It supports various
views of the original JSON data including plain and tabular output depending on
the endpoint. It is a dynamic tool based on parsing of the
[OpenAPI description](../../docs/openapi.json).

## Contributing

In order to contribute, you need to understand the
[OpenAPI specification](https://swagger.io/specification/). The specification
allows for extensions using fields that begin with `x-`. The HSE OpenAPI
description is marked up with extension fields in order to create a useful tool.

### Specification Extensions

#### `x-alias`

A few of the operations are commonly used, so providing an alias with a more
memorable value can be convenient.

##### Schmea

String matching `^[a-z]+[a-z-]?[a-z]+$`.

#### `x-hide`

Some of our operations are not particularly useful unless you really need that
information. If set to `true`, the operation will be hidden from the root help
output unless verbosity is enabled.

##### Schema

Boolean

#### `x-options`

Used to add options to a particular operation. This can include `help`,
`format`, or any other option.

##### Schema

Array of options:

```jsonc
[
  {
    // Long option name.
    "long": "string",
    // Short option name.
    "short": "string",
    // Description of the option.
    "description": "string",
    // Whether an argument is required for the option, assumed false.
    "requires-argument": "boolean (optional)",
    // Parameter that the option is tied to.
    "parameter": "pointer"
  }
]
```

#### `x-formats`

Used to describe various output formats that an operation supports.

##### Schema

```jsonc
{
  // Supports a JSON output.
  "json": {},
  // Supports a plain output.
  "plain": {},
  // Supports a tabular output.
  "tab": {
    // Type of tabular output.
    "type": "array|flattened|custom",
    // Depends on type.
    "config": {}
  }
}
```

###### Array Config

```jsonc
{
  "columns": {
    // Column header mapped to a JSON pointer that will index an entry in an
    // object of the array.
    "header": "pointer"
  }
}
```

###### Flattened Config

Used only for outputting `.../params` endpoints.

```jsonc
{
  // Must be a length of 2.
  "columns": [
    "header1",
    "header2"
  ]
}
```

###### Custom Config

`custom` views require a little bit of manual work. You must create a new `.c`
file that exports a few symbols based on the `operationId` of the operation
(request). Wherever your symbol has `-`, change it to `_` for the symbol names.

- `const char *$operationId_headers[]` of headers.
- `size_t $operationId_columnc` - number of headers.
- `enum $operationId_justify[]` - justification of columns.
- `merr_t $operationId_free_values(int len, char **values)` - free data that was
  previously allocated.
- `merr_t $operationId_parse_values(cJSON *body, int *len, char ***values)` -
function to parse the request output into an array of values. `len` is number
of rows. `values` is supposed to be allocated for `columnc * len` string
pointers.
