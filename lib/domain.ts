export const ALLOWED_EMAIL_DOMAIN = "@threatlocker.com";

export function isAllowedEmail(email: string) {
  return email.trim().toLowerCase().endsWith(ALLOWED_EMAIL_DOMAIN);
}
