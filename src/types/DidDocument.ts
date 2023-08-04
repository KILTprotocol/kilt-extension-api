import type { KiltAddress } from './Address'

/**
 * A string containing a KILT DID Uri.
 */


type DidUriVersion = '' | `v${string}:`
type AuthenticationKeyType = '00' | '01'
type LightDidEncodedData = '' | `:${string}`

export type DidUri =
  | `did:kilt:${DidUriVersion}${KiltAddress}`
  | `did:kilt:light:${DidUriVersion}${AuthenticationKeyType}${KiltAddress}${LightDidEncodedData}`

/**
 * The fragment part of the DID URI including the `#` character.
 */
export type UriFragment = `#${string}`
/**
 * URI for DID resources like keys or service endpoints.
 */
export type DidResourceUri = `${DidUri}${UriFragment}`


export type DidSignature = {
    keyUri: DidResourceUri
    signature: string
  }
