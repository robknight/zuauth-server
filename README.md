# ZuAuth Server

This demonstrates server-side verification of credentials from [Zupass](https://github.com/proofcarryingdata/zupass).

When using a client like [ZuAuth](https://github.com/cedoor/zuauth), you can verify credentials received from Zupass in the browser. This repository shows how you can verify those credentials on the server-side, and how you can generate a value to use as a 'watermark' in the proof generated for authentication.

### Why watermarking is important

By default, proofs do not contain unique or time-bound content, which means that they can be re-used. This is desirable in some circumstances, but is a bad property for an authentication credential.

To prevent credential re-use, `ZKEdDSAEventTicketPCD` credentials have a `watermark` argument, which can be populated with a unique single-use value provided by a server. The proof is generated on the client side, and the server checks to see if the expected watermark is included, which means that the server will not accept credentials that do not include the watermark.

In this code example, the API route `/api/nonce` generates a single-use value to be used as a watermark, and `/api/login` checks to see if it is present during verification.

## Installation

Run `yarn` or `npm install`.

## Running

Run `yarn dev` or `npm run dev`.

