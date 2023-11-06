import { EdDSAPublicKey, isEqualEdDSAPublicKey } from "@pcd/eddsa-pcd";

const ticketTypeNames = [
  "ZuzaluResident",
  "ZuzaluOrganizer",
  "ZuzaluVisitor",
  "ZuConnectResident"
] as const;

type TicketTypeName = (typeof ticketTypeNames)[number];

const zupassPublicKey = JSON.parse(process.env.ZUPASS_PUBLIC_KEY as string);

interface TicketSpec {
  eventId: string;
  productId: string;
  publicKey: EdDSAPublicKey;
}

/**
 * We want to match a ticket based on a pairing of event IDs and product IDs.
 * We also want to divide these into categories or "types" of ticket. There
 * are four types, as defined above, and each type has one or more pairs of
 * event and product IDs that qualify a ticket as belonging to that group.
 *
 * With this data, we can classify a user's ticket and use this to make some
 * decisions about what access to grant, or other features to enable or
 * disable.
 */
const ticketTypes: Record<
  TicketTypeName,
  Array<TicketSpec>
> = {
  ZuzaluResident: [
    {
      eventId: "5de90d09-22db-40ca-b3ae-d934573def8b",
      productId: "5ba4cd9e-893c-4a4a-b15b-cf36ceda1938",
      publicKey: zupassPublicKey
    }
  ],
  ZuzaluOrganizer: [
    {
      eventId: "5de90d09-22db-40ca-b3ae-d934573def8b",
      productId: "10016d35-40df-4033-a171-7d661ebaccaa",
      publicKey: zupassPublicKey
    }
  ],
  ZuzaluVisitor: [
    {
      eventId: "5de90d09-22db-40ca-b3ae-d934573def8b",
      productId: "53b518ed-e427-4a23-bf36-a6e1e2764256",
      publicKey: zupassPublicKey
    }
  ],
  ZuConnectResident: [
    {
      eventId: "91312aa1-5f74-4264-bdeb-f4a3ddb8670c",
      productId: "cc9e3650-c29b-4629-b275-6b34fc70b2f9",
      publicKey: zupassPublicKey
    },
    {
      eventId: "54863995-10c4-46e4-9342-75e48b68d307",
      productId: "d2123bf9-c027-4851-b52c-d8b73fc3f5af",
      publicKey: zupassPublicKey
    },
    {
      eventId: "797de414-2aec-4ef8-8655-09df7e2b6cc6",
      productId: "d3620f38-56a9-4235-bea8-0d1dba6bb623",
      publicKey: zupassPublicKey
    },
    {
      eventId: "a6109324-7ca0-4198-9583-77962d1b9d53",
      productId: "a6109324-7ca0-4198-9583-77962d1b9d53",
      publicKey: zupassPublicKey
    }
  ]
};

// Map the above data structure into a simple array of event IDs.
export const supportedEvents = Object.values(ticketTypes).flatMap((items) =>
  items.map((item) => item.eventId)
);

/**
 * Use the above data structure to map a ticket's event ID and product ID to
 * a known ticket type, if any exists. Returns undefined if no match is found.
 */
export function matchTicketToType(
  eventIdToMatch: string,
  productIdToMatch: string,
  publicKeyToMatch: EdDSAPublicKey
): TicketTypeName | undefined {
  for (const name of ticketTypeNames) {
    for (const { eventId, productId, publicKey } of ticketTypes[name]) {
      if (eventId === eventIdToMatch &&
          productId === productIdToMatch &&
          isEqualEdDSAPublicKey(publicKey, publicKeyToMatch)) {
        return name;
      }
    }
  }

  return undefined;
}