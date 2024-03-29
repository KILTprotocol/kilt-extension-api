/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { ApiWindow, InjectedWindowProvider, PubSubSessionV1, PubSubSessionV2 } from '../types/index.js'

// cross-environment reference to global object (aka 'window' in browser environments)
const apiWindow = globalThis as Window & ApiWindow

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

export type WatchExtensionsCallback = (
  extensions: Array<InjectedWindowProvider<PubSubSessionV1 | PubSubSessionV2>>
) => void

/**
 * @private
 * This function relies on API that is not part of the Credential API standard yet and might break at any point in time.
 *
 * Watch for new extensions that get injected.
 *
 * Each time an extension has injected itself, it will dispatch an event.
 * This function calls the provided callback with all available extensions when such an event is received.
 *
 * NOTE: Use the returned cleanup function to remove the event listener when the callback is not needed anymore.
 *
 * @param callback Callback that gets called each time a new extension is injected.
 * @returns Cleanup function which removes the listener for new extensions.
 */
export function watchExtensions(callback: WatchExtensionsCallback): () => void {
  function handler() {
    callback(getExtensions())
  }

  window.addEventListener('kilt-extension#initialized', handler)
  return () => {
    window.removeEventListener('kilt-extension#initialized', handler)
  }
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
        credentials: '3.2',
      },
    },
    enumerable: false,
  })

  apiWindow.dispatchEvent(new CustomEvent('kilt-dapp#initialized'))
}
