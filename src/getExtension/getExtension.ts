import {
  ApiWindow,
  InjectedWindowProvider,
  PubSubSessionV1,
  PubSubSessionV2,
} from '../types/types'

const apiWindow = window as Window & ApiWindow

/**
 * Get all extensions that are currently initialized and support the Credential API.
 * 
 * Note that this method only returns the extensions that are initialized at the time when this function is called.
 * If an extension injects itself only after this function is called, it will not be contained in the returned extensions.
 * @returns an object containing extensions
 */
export function getExtensions(): Record<string, InjectedWindowProvider<PubSubSessionV1 | PubSubSessionV2>> {

  // copy all extensions into a new object since the caller should be allowed to change the object
  // without changing the underlying extension object.
  return { ...apiWindow.kilt }
}

/**
 * This function enables the communication with extensions supporting the Credential API.
 *
 * The `meta` property of `window.kilt` is set according to the Credential API.
 * After this is done an event is dispatched to notify all extensions that they should inject themselves now.
 */
export function initializeKiltExtensionAPI() {
  apiWindow.kilt = apiWindow.kilt || {}

  Object.defineProperty(apiWindow.kilt, 'meta', {
    value: {
      versions: {
        credentials: '3.0'
      }
    },
    enumerable: false
  })

  apiWindow.dispatchEvent(new CustomEvent('kilt-dapp#initialized'))
}
