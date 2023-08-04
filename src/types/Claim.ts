import type { CTypeHash } from './CType'
import type { DidUri } from './DidDocument'

type ClaimPrimitives = string | number | boolean

export interface IClaimContents {
  [key: string]:
    | ClaimPrimitives
    | IClaimContents
    | Array<ClaimPrimitives | IClaimContents>
}

export interface IClaim {
  cTypeHash: CTypeHash
  contents: IClaimContents
  owner: DidUri
}

/**
 * The minimal partial claim from which a JSON-LD representation can be built.
 */
export type PartialClaim = Partial<IClaim> & Pick<IClaim, 'cTypeHash'>
