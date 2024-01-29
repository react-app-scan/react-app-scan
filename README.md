# ReactAppScan

ReactAppScan constructs a Component Graph (CoG) for tracking
React Data Flow and detect vulnerabilities following both JavaScript
and React data flows.

## Getting Started

To set up your environment for ReactAppScan, please refer to our [Setup Guide](./SETUP.md). This guide provides detailed instructions on how to install and configure all the necessary dependencies.

## Options

The following options are available:

- `input_file`: Source code file or directory of a package to generate a component graph for.

- `--timeout <seconds>`: Time limit for testing an entrance.

- `--run-env <path>`: Set the running environment location.

- `-t, --vul-type <type>`: Set the vulnerability type, e.g., 'xss', to be checked.

- `--babel <path>`: Use Babel to convert files first.

- `--export <mode>`: Export the graph to CSV files. Can be 'light' or 'all'.

- `--is-jsx-application`: Flag to run a JSX application.

- `--service-entry <path>`: If set, start from the path to register services.

- `--log-base-location <path>`: Specify the base location for logs.

- `--package-timeout <seconds>`: Time limit for testing a package.

- `--jsx-package`: Run a JSX package.
