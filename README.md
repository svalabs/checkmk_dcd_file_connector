# CSV Import

Import hosts from a CSV file.

[![pipeline status](https://codehub.sva.de/ops_mon/check_mk-csv-connector/badges/master/pipeline.svg)](https://codehub.sva.de/ops_mon/check_mk-csv-connector/-/commits/master)
[![coverage report](https://codehub.sva.de/ops_mon/check_mk-csv-connector/badges/master/coverage.svg)](https://codehub.sva.de/ops_mon/check_mk-csv-connector/-/commits/master)

This makes use of Check MKs [Dynamic Host Configuration (DCD)](https://docs.checkmk.com/latest/de/dcd.html) feature.

## Usage

After installation you will have to create a new connection using the _CSV Connector_ type.

You will have to specify an existing file that will be used for importing.

### CSV file

The first column in the CSV is expected to contain the hostname.

All other columns will be treated as tags by default.
You can prefix a column name with `tag_` for an explicit handling as a tag.
If you prefix the column with `label_` the contents of the column will be treated as a label.

#### Example

An file for an import might look like this:

```
HOSTNAME,STANDORT,STADT,IDENT
ABC001,DARZ,Darmstadt,NET
ABC002,WIRZ,Wiesbaden,NET
ABC003,WIRZ,Wiesbaden,SYS
ABC004,DARZ,Darmstadt,SYS
ABC005,DATU,Darmstadt,SYS
ABC006,DATU,Darmstadt,NET
```

## Building

The project creates a new `.mkp` file with every tag.
Adjust the version in the `info` file accordingly if you plan to release.
