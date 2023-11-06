import { hexToBigInt, toHexString, getRandomValues } from "@pcd/util";
import { ZKEdDSAEventTicketPCDPackage } from "@pcd/zk-eddsa-event-ticket-pcd";
import { Router } from "express";
import { ironSession } from "iron-session/express";
import { matchTicketToType  } from "./zupass-config";

declare module "iron-session" {
  interface IronSessionData {
    nonce?: string;
    user?: string;
  }
}

const session = ironSession(
{
  cookieName: process.env.SESSION_COOKIE_NAME as string,
  password: process.env.SESSION_PASSWORD as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production"
  }
});

const nullifiers = new Set();

const routes = Router();

routes.get("/", (req, res) => {
  return res.json({ message: "Hello World" });
});

routes.get("/api/nonce", session, async (req, res) => {
  try {
    req.session.nonce = hexToBigInt(
      toHexString(getRandomValues(30))
    ).toString();

    await req.session.save();

    res.status(200).send(req.session.nonce);
  } catch (error) {
    console.error(`[ERROR] ${error}`);
    res.send(500);
  }
});

routes.get("/api/login", session, async (req, res) => {
  try {
    // First ensure that a PCD was provided
    if (!req.body.pcd) {
      console.error(`[ERROR] No PCD specified`);

      res.status(400).send("No PCD specified");
      return;
    }

    const pcd = await ZKEdDSAEventTicketPCDPackage.deserialize(req.body.pcd);

    // Check that the proof matches the claim
    if (!(await ZKEdDSAEventTicketPCDPackage.verify(pcd))) {
      console.error(`[ERROR] ZK ticket PCD is not valid`);

      res.status(401).send("ZK ticket PCD is not valid");
      return;
    }

    // Check that the claim includes a watermark containing the session nonce
    if (pcd.claim.watermark.toString() !== req.session.nonce) {
      console.error(`[ERROR] PCD watermark doesn't match`);

      res.status(401).send("PCD watermark doesn't match");
      return;
    }

    // Check that the claim includes event and product IDs
    if (!pcd.claim.partialTicket.eventId || !pcd.claim.partialTicket.productId) {
      console.error(`[ERROR] PCD ticket does not have event ID or product ID and so cannot be authenticated`);

      res.status(401).send("PCD ticket does not have event ID or product ID and so cannot be authenticated");
      return;
    }

    // Check that the event ID, product ID, and signer match a known ticket
    // spec
    if (!matchTicketToType(pcd.claim.partialTicket.eventId, pcd.claim.partialTicket.productId, pcd.claim.signer)) {
      console.error(`[ERROR] PCD ticket is not supported`);

      res.status(401).send("PCD ticket not have a supported event ID, product ID, or signer");
      return;
    }

    // Check that the claim contains a nullifier hash
    if (!pcd.claim.nullifierHash) {
      console.error(`[ERROR] PCD ticket nullifier has not been defined`);

      res.status(401).send("PCD ticket nullifer has not been defined");
      return;
    }

    // Check that the nullifier has not already been used
    if (nullifiers.has(pcd.claim.nullifierHash)) {
      console.error(`[ERROR] PCD ticket has already been used`);

      res.status(401).send("PCD ticket has already been used");
      return;
    }

    // The PCD's nullifier is saved so that it prevents the
    // same PCD from being reused for another login.
    nullifiers.add(pcd.claim.nullifierHash);

    req.session.user = pcd.claim.partialTicket.attendeeEmail as string;

    await req.session.save();

    res.status(200).send({
      attendeeEmail: pcd.claim.partialTicket.attendeeEmail
    });
  } catch (error: any) {
    console.error(`[ERROR] ${error.message}`);

    res.status(500).send(`Unknown error: ${error.message}`);
  }
});

routes.get("/api/logout", session, (req, res) => {
  req.session.destroy();
  res.send({ ok: true });
});

export default routes;
