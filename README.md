# kilt-extension

KILT Extension helper functions. The tools you need to add a KILT extension to your app, or add KILT functionality to your extension.

## Get Extension

In order to use the extension with KILT credential API the extension needs to be injected into the application close to the loading of the application. Here you can use `getExtensions` function to add it directly to the application and wait for its response.

Now you can access the extensions API and handle the data and interactions between the Dapp and Extension.

See the `react-example.ts` example inside the get extension folder, here is how you can use `getExtensions` in a react app?

## Inject Extension

Currently work in progress.

## Did Configuration Resource

This library also helps with setting up the [Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/) as required by the [KILT Credential API specification](https://github.com/KILTprotocol/spec-ext-credential-api).

A CLI tool included in this library can be used to create a [Did Configuration Resource](https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource) as described by these specs that is needed to establish a secure, e2e encrypted communication channel between a conforming browser extension and application backend.

After installing this package globally our in your application directory, you can run the CLI tool from your commandline, e.g.:

```bash
yarn createDidConfig --did <your DID> --origin <your domain> --assertionMethod <id of your DIDs assertionMethod key> --seed <seed or mnemonic of the assertionMethod key>
```

Please refer to the CLI tool's helper for more information on additional commands and configuration, which is available via:

```bash
yarn createDidConfig --help
```
