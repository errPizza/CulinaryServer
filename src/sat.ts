import { z } from "zod";

// The business behind a license, as its Constancia de Situación Fiscal states it. The CSD the owner loads later must carry
// this same RFC, so these rules are the ones the branch applies again when it checks the certificate.

const DIGITS = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ Ñ";
const RFC_SHAPE = /^([A-ZÑ&]{3,4})(\d{2})(\d{2})(\d{2})([A-Z\d]{2})([A\d])$/;

/** The SAT check digit: modulus 11 over the first twelve characters, a 12-character RFC padded with a leading space. */
function checkDigit(rfc: string): boolean {

  const padded = rfc.length === 12 ? " " + rfc : rfc;
  let sum = 0;

  for (let i = 0; i < 12; i++) sum += DIGITS.indexOf(padded[i]!) * (13 - i);

  const rest = sum % 11;
  const expected = rest === 0 ? "0" : 11 - rest === 10 ? "A" : String(11 - rest);

  return padded[12] === expected;
}

/** Whether the six digits are a real date; the century does not matter for the check. */
function realDate(yy: string, mm: string, dd: string): boolean {

  const month = Number(mm), day = Number(dd);
  const date = new Date(Date.UTC(2000 + Number(yy), month - 1, day));

  return month >= 1 && month <= 12 && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

export type PersonType = "moral" | "fisica";

export function rfcProblem(rfc: string): string | null {

  const m = RFC_SHAPE.exec(rfc);

  if (!m) return "RFC: 3 letras (persona moral) o 4 (persona física), 6 dígitos de fecha y 3 de homoclave";
  if (!realDate(m[2]!, m[3]!, m[4]!)) return "RFC: la fecha no existe";
  if (rfc === "XAXX010101000" || rfc === "XEXX010101000") return "RFC: el genérico no identifica al negocio";
  if (!checkDigit(rfc)) return "RFC: el dígito verificador no corresponde; revísalo en la Constancia de Situación Fiscal";

  return null;
}

export const personType = (rfc: string): PersonType => (rfc.length === 12 ? "moral" : "fisica");

// c_RegimenFiscal of CFDI 4.0 and to whom each applies.
export const REGIMES: Record<string, { name: string; moral: boolean; fisica: boolean }> = {

  "601": { name: "General de Ley Personas Morales", moral: true, fisica: false },
  "603": { name: "Personas Morales con Fines no Lucrativos", moral: true, fisica: false },
  "605": { name: "Sueldos y Salarios e Ingresos Asimilados a Salarios", moral: false, fisica: true },
  "606": { name: "Arrendamiento", moral: false, fisica: true },
  "607": { name: "Régimen de Enajenación o Adquisición de Bienes", moral: false, fisica: true },
  "608": { name: "Demás ingresos", moral: false, fisica: true },
  "610": { name: "Residentes en el Extranjero sin Establecimiento Permanente en México", moral: true, fisica: true },
  "611": { name: "Ingresos por Dividendos (socios y accionistas)", moral: false, fisica: true },
  "612": { name: "Personas Físicas con Actividades Empresariales y Profesionales", moral: false, fisica: true },
  "614": { name: "Ingresos por intereses", moral: false, fisica: true },
  "615": { name: "Régimen de los ingresos por obtención de premios", moral: false, fisica: true },
  "616": { name: "Sin obligaciones fiscales", moral: false, fisica: true },
  "620": { name: "Sociedades Cooperativas de Producción que optan por diferir sus ingresos", moral: true, fisica: false },
  "621": { name: "Incorporación Fiscal", moral: false, fisica: true },
  "622": { name: "Actividades Agrícolas, Ganaderas, Silvícolas y Pesqueras", moral: true, fisica: false },
  "623": { name: "Opcional para Grupos de Sociedades", moral: true, fisica: false },
  "624": { name: "Coordinados", moral: true, fisica: false },
  "625": { name: "Actividades Empresariales con ingresos a través de Plataformas Tecnológicas", moral: false, fisica: true },
  "626": { name: "Régimen Simplificado de Confianza", moral: true, fisica: true }

};

// Regimes under which a restaurant cannot issue its own sales invoices.
const NOT_FOR_ISSUING = new Set(["605", "611", "614", "615", "616"]);

// The capital regime CFDI 4.0 asks to leave out of the name: S.A. DE C.V., SA DE CV, S. DE R.L. DE C.V., S.A.P.I., S.C., A.C. …
const CAPITAL_REGIME = /(^|[\s,])(S\.?\s?A\.?\s?P\.?\s?I\.?|S\.?\s?A\.?\s?B\.?|S\.?\s?A\.?\s?S\.?|S\.?\s?A\.?|S\.?\s?DE\s?R\.?\s?L\.?|S\.?\s?C\.?|A\.?\s?C\.?|S\.?\s?EN\s?C\.?|I\.?\s?A\.?\s?P\.?)(\s?DE\s?C\.?\s?V\.?)?\.?\s*$/;

/** The name as the SAT prints it: upper case and single spaces. The capital regime is refused, not removed, so nobody guesses. */
export function fiscalName(raw: string): string {

  return raw.normalize("NFC").toLocaleUpperCase("es-MX").replace(/\s+/g, " ").trim();
}

export const fiscalSchema = z.strictObject({

  rfc: z.string().trim().toUpperCase(),
  name: z.string().max(254),
  postalCode: z.string().trim(),
  regime: z.string().trim()

}).transform((f, ctx) => {

  const name = fiscalName(f.name);
  const fail = (path: string, message: string) => ctx.addIssue({ code: "custom", path: [path], message });
  const problem = rfcProblem(f.rfc);

  if (problem) fail("rfc", problem);
  if (name.length < 1) fail("name", "Razón social: requerida, tal como aparece en la Constancia de Situación Fiscal");
  if (CAPITAL_REGIME.test(name)) fail("name", "Razón social: sin el régimen societario (S.A. de C.V., S. de R.L., S.C., A.C.), como en la Constancia de Situación Fiscal");
  if (/[^A-ZÑÁÉÍÓÚÜ0-9&.,'\-/ ]/.test(name)) fail("name", "Razón social: sólo letras, dígitos y & . , ' - /");
  if (!/^\d{5}$/.test(f.postalCode) || f.postalCode.startsWith("00")) fail("postalCode", "Código postal fiscal: 5 dígitos de un código postal existente");

  const regime = REGIMES[f.regime];

  if (!regime) fail("regime", "Régimen fiscal: clave del catálogo c_RegimenFiscal del SAT");
  else if (!problem && !regime[personType(f.rfc)]) fail("regime", `Régimen fiscal: ${f.regime} no aplica a una persona ${personType(f.rfc) === "moral" ? "moral" : "física"}`);
  else if (NOT_FOR_ISSUING.has(f.regime)) fail("regime", `Régimen fiscal: con ${f.regime} no se emiten facturas de venta`);

  return { rfc: f.rfc, name, postalCode: f.postalCode, regime: f.regime };

});

export type Fiscal = z.output<typeof fiscalSchema>;
