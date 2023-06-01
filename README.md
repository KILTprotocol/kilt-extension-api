# kilt-extension-api

KILT Extension helper functions. The tools you need to add a KILT extension to your app, or add KILT functionality to your extension.

## Get Extension

In order to use the extension with KILT credential API the extension needs to be injected into the application close to the loading of the application. Here you can use `getExtensions` function to add it directly to the application and wait for its response.

Now you can access the extensions API and handle the data and interactions between the Dapp and Extension.

See the `react-example.ts` example inside the get extension folder, here is how you can use `getExtensions` in a react app?

## Inject Extension

Currently work in progress.

## DID Configuration Resource

This library also helps with setting up the [Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/) as required by the [KILT Credential API specification](https://github.com/KILTprotocol/spec-ext-credential-api).

A CLI tool included in this library can be used to create a [Did Configuration Resource](https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource) as described by these specs that is needed to establish a secure, e2e encrypted communication channel between a conforming browser extension and application backend.

To start using this tool, add this package to your application (`yarn add --dev kilt-extension-api`) or install it globally if you need to use it outside of your application directory (`yarn global add kilt-extension-api`).

You can then run the CLI tool as yarn executable, e.g.:

```bash
yarn createDidConfig --did <your DID> --origin <your domain> --assertionMethod <id of your DIDs assertionMethod key> --seed <seed or mnemonic of the assertionMethod key>
```

Please refer to the CLI tool's helper for more information on additional commands and configuration, which is available via:

```bash
yarn createDidConfig --help
```

### Creating a DID Config programatically

Functionality similar to that of the CLI tool is available for import into your Node.js scripts via the subpath `kilt-extension-api/wellKnownDidConfiguration`:

```ts
import { createCredential, didConfigResourceFromCredential } from './wellKnownDidConfiguration/index.js'

const credential = await createCredential(
  ({ data }) => {
    //...DID signing logic
  },
  'https://example.com',
  'did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare'
)
const didConfigResource = didConfigResourceFromCredential(credential)
```

This module also helps with verifying a DID configuration resource within an extension context:

```ts
import { verifyDidConfigResource } from './wellKnownDidConfiguration/index.js'

// load didConfigResource from https://example.com/.well-known/did-configuration.json

const didLinkedToOrigin = await verifyDidConfigResource(didConfigResource, 'https://example.com')

// or, if a specific DID is expected:

await verifyDidConfigResource(
  didConfigResource,
  'https://example.com',
  'did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare'
)
```
