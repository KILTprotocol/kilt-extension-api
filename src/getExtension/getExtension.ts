import {
  ApiWindow,
  InjectedWindowProvider,
  PubSubSessionV1,
  PubSubSessionV2,
} from '../types/types'

// cross-environment reference to global object (aka 'window' in browser environments)
const apiWindow = globalThis as Window & ApiWindow

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
