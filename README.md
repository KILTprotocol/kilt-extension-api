# kilt-extension-api

KILT Extension helper functions.
The tools you need to communicate with KILT enabled extensions.

# How to use this library

Note that `initializeKiltExtensionAPI()` needs to be called before any communication with KILT extensions can happen!

## initialize KILT Extension API

We need to signal to the extensions which API versions we currently support, so that the extension can inject the appropriate scripts into the website.
This library only supports a single API version at a time.

```js
import { initializeKiltExtensionAPI } from 'kilt-extension-api'

initializeKiltExtensionAPI()
```

## Get Extension

`getExtensions` returns a list of extensions that are currently injected to the website.

```js
import { getExtensions } from 'kilt-extension-api'

const extensions = getExtensions()
```

## Watch Extensions

Extensions might take longer to load than the website.
In that case the first call to `getExtensions()` might not return all available extensions.

To list additional extensions as they load, you can use `watchExtensions`.

Here is an example how you could use this function in a React application

```js
import { watchExtensions, Types } from 'kilt-extension-api'

export default function Home(): JSX.Element {
  const [extensions, setExtensions] = useState<
    Types.InjectedWindowProvider<Types.PubSubSessionV1 | Types.PubSubSessionV2>[]
  >([])
  async function testApi() {
    const result = await fetch('/api')
    const message = await result.json()
    console.log(message)
  }

  useEffect(() => watchExtensions((extensions) => {
    setExtensions(extensions)
  }), [])

  return <>
    <h2>Extensions</h2>
    <ul>
    {
      extensions.map((ext, i) => (
        <li key={i}>{ext.name}</li>
      ))
    }
    </ul>
  </>
}
```

## Well-Known DID Configuration

This library also helps with setting up the [Well-Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/) as required by the [KILT Credential API specification](https://github.com/KILTprotocol/spec-ext-credential-api).

A CLI tool included in this library can be used to create a [DID Configuration Resource](https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource) as described by these specs that is needed to establish a secure, e2e encrypted communication channel between a conforming browser extension and application backend.

To start using this tool, add this package to your application (`yarn add --dev kilt-extension-api`) or install it globally if you need to use it outside of your application directory (`yarn global add kilt-extension-api`).

### Use the command line

You can then run the CLI tool as yarn executable, e.g.:

```bash
yarn createDidConfig --did <your DID> --origin <your domain> --assertionMethod <id of your DIDs assertionMethod key> --seed <seed or mnemonic of the assertionMethod key>
```

Please refer to the CLI tool's helper for more information on additional commands and configuration, which is available via:

```bash
yarn createDidConfig --help
```

### Integrate into your app

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
