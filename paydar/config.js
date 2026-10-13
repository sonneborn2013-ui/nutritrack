/* Configuración de Paydar.
 * Llena estos 3 valores después de crear tu proyecto en Supabase (ver LEEME.md).
 * Si los dejas vacíos, la app funciona igual pero SIN cuenta en la nube ni avisos con la app cerrada.
 * Estos valores son PÚBLICOS (no son secretos): la seguridad la dan las reglas RLS y el cifrado.
 */
window.PAYDAR_CONFIG = {
  supabaseUrl: '',      // ej. 'https://abcdefghijk.supabase.co'
  supabaseAnonKey: '',  // Project Settings → API → "anon public"
  vapidPublicKey: '',   // la llave PÚBLICA generada con tools/generar-llaves-avisos.html
  appUrl: 'https://sonneborn2013-ui.github.io/nutritrack/paydar/',           // opcional: dirección pública de la app, ej. 'https://tuusuario.github.io/paydar/'
  aiEnabled: false,     // true cuando ya desplegaste la función ai-extract (lectura de fotos y dictado con IA)
};
