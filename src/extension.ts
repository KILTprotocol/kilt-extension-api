import { DidPublicKey, IEncryptedMessage } from '@kiltprotocol/sdk-js'

type This = typeof globalThis
export interface PubSubSession {
  listen: (
    callback: (message: IEncryptedMessage) => Promise<void>
  ) => Promise<void>
  close: () => Promise<void>
  send: (message: IEncryptedMessage) => Promise<void>
  encryptionKeyId: DidPublicKey['id']
  encryptedChallenge: string
  nonce: string
}

export interface InjectedWindowProvider {
  signWithDid: (
    plaintext: string
  ) => Promise<{ signature: string; didKeyUri: string }>
  startSession: (
    dAppName: string,
    dAppEncryptionKeyId: DidPublicKey['id'],
    challenge: string
  ) => Promise<PubSubSession>
  specVersion: '0.1'
  version: string
}

interface ApiWindow extends This {
  kilt: Record<string, InjectedWindowProvider>
}

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

export function injectExtension(): Promise<InjectedWindowProvider[]> {
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
