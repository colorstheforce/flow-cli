---
title: Remove a Contract with the Fow CLI
sidebar_title: Remove a Contract
description: How to remove an existing contract
---

Remove an existing contract deployed to an account on the Flow network using Flow CLI.

`flow accounts remove-contract <name>`

## Example Usage

```shell
flow accounts remove-contract FungibleToken ./FungibleToken.cdc
```

### Example response

```shell
Contract 'FungibleToken' removed from account '0xf8d6e0586b0a20c7'

Address	 0xf8d6e0586b0a20c7
Balance	 0
Keys	 1

Key 0	Public Key		 640a5a359bf3536d15192f18d872d57c98a96cb871b92b70cecb0739c2d5c37b4be12548d3526933c2cda9b0b9c69412f45ffb6b85b6840d8569d969fe84e5b7
Weight			 1000
Signature Algorithm	 ECDSA_P256
Hash Algorithm		 SHA3_256

Contracts Deployed: 0
```

## Arguments

### Name
- Name: `name`
- Valid inputs: Any string value

Name of the contract as it is defined in the contract source code.

## Flags

### Signer

- Flag: `--signer`
- Valid inputs: the name of an account defined in the configuration (`flow.json`)

Specify the name of the account that will be used to sign the transaction.


### Host
- Flag: `--host`
- Valid inputs: an IP address or hostname.
- Default: `127.0.0.1:3569` (Flow Emulator)

Specify the hostname of the Access API that will be
used to execute the commands.

### Network

- Flag: `--network`
- Short Flag: `-n`
- Valid inputs: the name of a network defined in the configuration (`flow.json`)

Specify which network you want the command to use for execution.

### Filter

- Flag: `--filter`
- Short Flag: `-x`
- Valid inputs: case-sensitive name of the result property.

Specify any property name from the result you want to return as the only value.

### Output

- Flag: `--output`
- Short Flag: `-o`
- Valid inputs: `json`, `inline`

Specify in which format you want to display the result.

### Save

- Flag: `--save`
- Short Flag: `-s`
- Valid inputs: valid filename

Specify the filename where you want the result to be saved.

### Log

- Flag: `--log`
- Short Flag: `-l`
- Valid inputs: `none`, `error`, `debug`
- Default: `info`

Specify the log level. Control how much output you want to see while command execution.

### Configuration

- Flag: `--conf`
- Short Flag: `-f`
- Valid inputs: valid filename

Specify filename for the configuration files, you can provide multiple configuration
files by using `-f` flag multiple times.