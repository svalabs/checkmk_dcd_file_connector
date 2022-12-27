# File Connector

Import hosts from a file in CSV, JSON or BVQ format.
This makes use of Check MKs [Dynamic Host Configuration (DCD)](https://docs.checkmk.com/latest/en/dcd.html) feature.

## Download

You can download releases of this package from [fileconnector @ checkmk exchange](https://exchange.checkmk.com/p/fileconnector).

The source code is available at [GitHub: svalabs/checkmk_dcd_file_connector](https://github.com/svalabs/checkmk_dcd_file_connector/).

## Usage

After [installation](https://docs.checkmk.com/latest/en/mkps.html#_installing_an_mkp) you will have to create a new connection using the _File Import_ connector type.

You will have to specify an existing file that will be used for importing.
Alongside that you have to choose the format your data is in.

The plugin tries to detect IP addresses and set them accordingly on your hosts. Field names that are assumed to contain an IP are `ipv4`, `ip`, `ipaddress`.

### Managing different host properties

The plugin supports handling different properties of a host.
This is achieved by using column or field names with special prefixes.

If you prefix the column with `label_` the contents of the column will be treated as a label. This is the default behaviour if neither one of the specific keywords nor another prefix is used.

You can prefix a column name with `tag_` for an explicit handling as a tag (tag group). Please make sure that you reference the tag ID so that a match can be made, i.e. to match the ID `flower` you have to write `tag_flower`.
Handling of tags is possible with checkmk instances using the deprecated web API (until 2.1) or with instances that support [werk 13964](https://checkmk.com/de/werk/13964).

If you prefix the column with `attr_` the contents will be handled as an attribute. Please make sure to  Missing attributes have to be created manually, the connector will not create these.

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
