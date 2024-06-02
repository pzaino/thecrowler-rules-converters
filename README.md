# The CROWler Rules Converters

## Introduction

The CROWler Rules Converters are a set of tools that allow to convert the
 rules of some similar rule-based systems to the CROWler rules format.

**Please Note**: This is a work in progress. The converters are not yet
complete and may not work as expected.

If you need the CROWler, you can find it [here](https://github.com/pzaino/thecrowler)

## Installation

To install the CROWler Rules Converters, you need to have Go Lang 1.22
or later installed on your system and you need to know how to use it.

To install just build the tools you need, for example to convert the
ruleset from Webalizer to CROWler rules, you need to build only the
convertWebalizer tool in the cmd directory.

```bash
go build ./cmd/convertWebalizer
```

This will create an executable file named `convertWebalizer` in the
current directory.

## Usage

All the provided tools work exactly in the same way. They read the
rules from a file and write the converted rules to another file.

To convert a ruleset called `technologies.json` from the Webalizer
format to the CROWler format, you can use the following command:

```bash
./convertWebalizer -i technologies.json -o ./output_path/
```

This will read the rules from the `technologies.json` file and write
a set of files in the `./output_path/` directory.

Once the rules are generated, you can check them for correctness and
, if everything went well, you can use them in the CROWler.

Have fun!

## License

The CROWler Rules Converters are released under the Apache 2.0. For more
information, please see the [LICENSE](LICENSE) file.

## Contributing

If you want to contribute to the CROWler Rules Converters, please read
the [CONTRIBUTING](CONTRIBUTING.md) file for more information.

## Contributors

- [@pzaino](https://github.com/pzaino) <br> <img src="https://avatars.githubusercontent.com/u/pzaino?v=4" width="50" height="50"/>
