/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { ICType } from '@kiltprotocol/types'
import { IMessage, MessageBody } from '../types/index.js'
import * as MessageError from './Error.js'
import { CType } from '@kiltprotocol/credentials'
import { UUID } from '@kiltprotocol/utils'

/**
 * Constructs a message from a message body.
 * This should be encrypted with [[encrypt]] before sending to the receiver.
 *
 * @param body The body of the message.
 * @param sender The DID of the sender.
 * @param receiver The DID of the receiver.
 * @returns The message created.
 */

export function fromBody<Body extends MessageBody>(
  body: Body,
  sender: IMessage['sender'],
  receiver: IMessage['receiver']
): IMessage<Body> {
  return {
    body,
    createdAt: Date.now(),
    receiver,
    sender,
    messageId: UUID.generate(),
  }
}

/**
 * Verifies required properties for a given [[CType]] before sending or receiving a message.
 *
 * @param requiredProperties The list of required properties that need to be verified against a [[CType]].
 * @param cType A [[CType]] used to verify the properties.
 */
export function verifyRequiredCTypeProperties(requiredProperties: string[], cType: ICType): void {
  CType.verifyDataStructure(cType as ICType)

  const unknownProperties = requiredProperties.find((property) => !(property in cType.properties))
  if (unknownProperties) {
    throw new MessageError.CTypeUnknownPropertiesError()
  }
}
