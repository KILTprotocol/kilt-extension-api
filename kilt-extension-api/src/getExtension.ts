import {
  ApiWindow,
  InjectedWindowProvider,
  PubSubSessionV1,
  PubSubSessionV2,
} from './types'

const apiWindow = window as Window & ApiWindow

/**
 * Get all extensions that are currently initialized and support the Credential API.
 *
 * Note that this method only returns the extensions that are initialized at the time when this function is called.
 * If an extension injects itself only after this function is called, it will not be contained in the returned extensions.
 *
 * @returns an array of extensions
 */
export function getExtensions(): Array<InjectedWindowProvider<PubSubSessionV1 | PubSubSessionV2>> {

  // Remove the meta object and return a list of extension objects
  return Object.values(apiWindow.kilt)
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
