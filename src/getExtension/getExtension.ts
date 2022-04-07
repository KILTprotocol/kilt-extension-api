import { ApiWindow, InjectedWindowProvider } from '../types/types'

const apiWindow = window as Window & ApiWindow

function documentReadyPromise<T>(creator: () => Promise<T>): Promise<T> {
  return new Promise((resolve): void => {
    if (document.readyState === 'complete') {
      resolve(creator())
    } else {
      window.addEventListener('load', () => resolve(creator()))
    }
  })
}

function getWindowExtensions(): Promise<[InjectedWindowProvider][]> {
  return Promise.all(
    Object.entries(apiWindow.kilt).map(
      ([name, { version, signWithDid, startSession, specVersion }]): Promise<
        [InjectedWindowProvider]
      > =>
        Promise.all([
          Promise.resolve({
            name,
            version,
            signWithDid,
            startSession,
            specVersion,
          }),
        ])
    )
  )
}

export function getExtensions(): Promise<InjectedWindowProvider[]> {
  apiWindow.kilt = apiWindow.kilt || {}

  return documentReadyPromise(
    (): Promise<InjectedWindowProvider[]> =>
      getWindowExtensions()
        .then((values): InjectedWindowProvider[] =>
          values
            .filter((value): value is [InjectedWindowProvider] => !!value[0])
            .map(([info]): any => info)
        )
        .catch((): any[] => [])
        .then((values): InjectedWindowProvider[] => values)
  )
}
