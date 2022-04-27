# File Connector

Import hosts from a file in CSV, JSON or BVQ format.
This makes use of Check MKs [Dynamic Host Configuration (DCD)](https://docs.checkmk.com/latest/de/dcd.html) feature.

## Usage

After installation you will have to create a new connection using the _File Import_ connector type.

You will have to specify an existing file that will be used for importing.
Alongside that you have to choose the format your data is in.

The plugin tries to detect IP addresses and set them accordingly on your hosts. Field names that are assumed to contain an IP are `ipv4`, `ip`, `ipaddress`.

### Managing different host attributes

The plugin supports handling different attributes of a host.

This is achieved by using column or field names with special prefixes.

You can prefix a column name with `tag_` for an explicit handling as a tag.
If you prefix the column with `label_` the contents of the column will be treated as a label.
If you prefix the column with `attr_` the contents will be handled as an attribute. Missing attributes have to be created manually.

Without a given prefix the columns will be treated as tags by default.

## File Formats

The importer supports various file formats.

### CSV file

The first column in the CSV is expected to contain the hostname.

#### Example

A file for an import might look like this:

```csv
HOSTNAME,STANDORT,STADT,IDENT
ABC001,DARZ,Darmstadt,NET
ABC002,WIRZ,Wiesbaden,NET
ABC003,WIRZ,Wiesbaden,SYS
ABC004,DARZ,Darmstadt,SYS
ABC005,DATU,Darmstadt,SYS
ABC006,DATU,Darmstadt,NET
```

### JSON file

The file is to be expected to contain an array of JSON objects.

It will try to detect the field that contains the hostname.
If it fails it will try to find a field with an IP.

#### Example

A file for an import might look like this:

```json
[
  {
    "hostname": "ABC001",
    "STANDORT": "DARZ",
    "STADT": "Darmstadt",
    "IDENT": "NET"
  },
  {
    "hostname": "ABC002",
    "STANDORT": "WIRZ",
    "STADT": "Wiesbaden",
    "IDENT": "NET"
  }
]
```

### BVQ file

It is possible to import an BVQ state file by selecting the
corresponding _Data Format_ during the connection configuration.

## Troubleshooting

### Logs

The connector uses the DCD logging.
Please keep in mind that there are separate log settings for the DCD that allow increasing the log level only for DCD.

You can also have a look at the [log file](https://docs.checkmk.com/latest/en/dcd.html#_dcd_log_file).

### omd restart

If problems occur after an update it is recommend run an `omd restart` once.

It is also recommended to execute `omd restart` if you happen to stumble upon an error message like `Skipping connection 'import_hosts' because of unknown connector type 'fileconnector'` or `Failed to get the status from DCD (The connection 'con_1' does not exist)`.
