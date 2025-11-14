import { encryptFlag, hashCookie } from "./crypto";
import { randomBytes } from "crypto";

const PLAINTEXT_FLAG = "VNFLAG{HUONG_SUOI_TO_QUOC_VIETNAM_CHI_DANH_CHO_TUONG_LAI_7m1R9k4P2Q8z3L6f0B5}";

export const ENCRYPTED_FLAG = encryptFlag(PLAINTEXT_FLAG);

export const ADMIN_COOKIE_VALUE = `admin_session=YWRtaW5fN2YzYTljMWUtODViMi00ZDhjLWIxMmYtOGE5NGU2ZDJjNWEx; flag=${PLAINTEXT_FLAG}`;

export const ADMIN_COOKIE_HASH = hashCookie(ADMIN_COOKIE_VALUE);

export function generateVisitNonce(): string {
  return randomBytes(32).toString('hex');
}
