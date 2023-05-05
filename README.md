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

To list additional extensions as they arrive, you can use `watchExtensions`.

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
