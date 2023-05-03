import {
  ApiWindow,
  InjectedWindowProvider,
  PubSubSessionV1,
  PubSubSessionV2,
} from '../types/types'

const apiWindow = window as Window & ApiWindow

function documentReadyPromise<T>(creator: () => T): Promise<T> {
  return new Promise((resolve): void => {
    if (document.readyState === 'complete') {
      resolve(creator())
    } else {
      window.addEventListener('load', () => resolve(creator()))
    }
  })
}

export function getExtensions(): Promise<
  Record<string, InjectedWindowProvider<PubSubSessionV1 | PubSubSessionV2>>
> {
  apiWindow.kilt = apiWindow.kilt || {}

  return documentReadyPromise(() => apiWindow.kilt)
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
