// Satanabe Remote API - comunicacao administrativa e teste de cliente.
// Deploy com verify_jwt = false: todas as rotas autenticam dentro da funcao.
// SUPABASE_SERVICE_ROLE_KEY fica APENAS no ambiente seguro da Edge Function.
import { createClient } from 'npm:@supabase/supabase-js@2.75.0';

const URL = Deno.env.get('SUPABASE_URL') ?? '';
const secretKeys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') ?? '{}');
const publishableKeys = JSON.parse(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') ?? '{}');
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || secretKeys.default || '';
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY') || publishableKeys.default || '';
if (!URL || !SERVICE_KEY || !ANON_KEY) throw new Error('Variaveis Supabase ausentes');
const svc = createClient(URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const authClient = createClient(URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-device-token',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};
const uuid = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: cors });
const err = (error: string, status = 400) => json({ ok: false, error }, status);
const hex = (bytes: Uint8Array) => Array.from(bytes).map(x => x.toString(16).padStart(2, '0')).join('');
async function sha256(s: string) { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))); }

async function authenticatedUser(req: Request) {
  const h = req.headers.get('authorization') ?? '';
  const match = /^Bearer (\S+)$/i.exec(h);
  if (!match) return null;
  const { data, error } = await authClient.auth.getUser(match[1]);
  return error ? null : data.user;
}

async function authenticatedDevice(req: Request, id: unknown) {
  const token = req.headers.get('x-device-token') ?? '';
  if (!uuid(id) || !/^[0-9a-f]{64}$/i.test(token)) return null;
  const digest = await sha256(token);
  const { data, error } = await svc.from('remote_devices')
    .select('id, owner_id').eq('id', id).eq('device_secret_hash', digest).maybeSingle();
  return error ? null : data;
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (req.method !== 'POST') return err('Somente POST', 405);
  try {
    const raw = await req.text();
    if (raw.length > 12000) return err('Requisicao muito grande', 413);
    const b = JSON.parse(raw || '{}');
    if (!b || typeof b !== 'object' || Array.isArray(b)) return err('JSON invalido');
    const action = b.action;

    // Chamadas do aplicativo / simulador com credencial unica por dispositivo.
    if (action === 'poll' || action === 'ack') {
      const device = await authenticatedDevice(req, b.device_id);
      if (!device) return err('Dispositivo nao autorizado', 401);
      if (action === 'poll') {
        await svc.from('remote_devices').update({ last_seen_at: new Date().toISOString() }).eq('id', device.id);
        const { data, error } = await svc.from('remote_commands')
          .select('id, command, payload, created_at')
          .eq('device_id', device.id).eq('owner_id', device.owner_id).eq('status', 'pending')
          .order('created_at', { ascending: true }).limit(20);
        return error ? err('Erro ao consultar comandos', 500) : json({ ok: true, commands: data });
      }
      if (!uuid(b.command_id) || !['applied', 'failed'].includes(b.status)) return err('Confirmacao invalida');
      const { data, error } = await svc.from('remote_commands')
        .update({ status: b.status, processed_at: new Date().toISOString() })
        .eq('id', b.command_id).eq('device_id', device.id)
        .eq('owner_id', device.owner_id).eq('status', 'pending')
        .select('id, status').maybeSingle();
      if (error) return err('Erro ao confirmar comando', 500);
      if (!data) return err('Comando nao encontrado ou ja confirmado', 404);
      return json({ ok: true, command: data });
    }

    // Acoes do administrador: token JWT de uma conta no Supabase Auth.
    const user = await authenticatedUser(req);
    if (!user) return err('Entre com uma conta autorizada', 401);
    if (action === 'create_device') {
      const name = typeof b.name === 'string' ? b.name.trim().slice(0, 48) : 'iPhone 2';
      if (!name) return err('Nome do dispositivo ausente');
      const { count, error: countError } = await svc.from('remote_devices')
        .select('id', { count: 'exact', head: true }).eq('owner_id', user.id);
      if (countError) return err('Nao foi possivel validar dispositivos', 500);
      if ((count ?? 0) >= 10) return err('Limite de 10 dispositivos', 429);
      const token = hex(crypto.getRandomValues(new Uint8Array(32)));
      const { data, error } = await svc.from('remote_devices')
        .insert({ owner_id: user.id, name, device_secret_hash: await sha256(token) })
        .select('id, name, created_at').single();
      return error ? err('Nao foi possivel criar dispositivo', 500) : json({ ok: true, device: data, device_token: token });
    }
    if (action === 'list_devices') {
      const { data, error } = await svc.from('remote_devices')
        .select('id, name, last_seen_at, created_at')
        .eq('owner_id', user.id).order('created_at', { ascending: false });
      return error ? err('Nao foi possivel listar dispositivos', 500) : json({ ok: true, devices: data });
    }
    if (action === 'send_command') {
      if (!uuid(b.device_id)) return err('Dispositivo invalido');
      if (!['ping', 'set_state'].includes(b.command)) return err('Comando nao autorizado');
      const payload = b.command === 'ping' ? {} : b.payload;
      if (b.command === 'set_state' && (
        !payload || typeof payload !== 'object' || Array.isArray(payload) ||
        typeof payload.key !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/i.test(payload.key) ||
        typeof payload.value !== 'boolean'
      )) return err('Estado invalido: informe key e value booleano');
      const { data: device } = await svc.from('remote_devices').select('id')
        .eq('id', b.device_id).eq('owner_id', user.id).maybeSingle();
      if (!device) return err('Dispositivo nao pertence a sua conta', 403);
      const { count } = await svc.from('remote_commands').select('id', { count: 'exact', head: true })
        .eq('owner_id', user.id).eq('device_id', b.device_id).eq('status', 'pending');
      if ((count ?? 0) >= 100) return err('Fila do dispositivo cheia', 429);
      const { data, error } = await svc.from('remote_commands')
        .insert({ owner_id: user.id, device_id: device.id, command: b.command, payload })
        .select('id, status, created_at').single();
      return error ? err('Falha ao enviar comando', 500) : json({ ok: true, command: data });
    }
    if (action === 'list_commands') {
      if (!uuid(b.device_id)) return err('Dispositivo invalido');
      const { data: device } = await svc.from('remote_devices').select('id')
        .eq('id', b.device_id).eq('owner_id', user.id).maybeSingle();
      if (!device) return err('Dispositivo nao pertence a sua conta', 403);
      const { data, error } = await svc.from('remote_commands')
        .select('id, command, payload, status, created_at, processed_at')
        .eq('owner_id', user.id).eq('device_id', device.id)
        .order('created_at', { ascending: false }).limit(40);
      return error ? err('Falha ao consultar historico', 500) : json({ ok: true, commands: data });
    }
    if (action === 'revoke_device') {
      if (!uuid(b.device_id)) return err('Dispositivo invalido');
      const { data, error } = await svc.from('remote_devices').delete()
        .eq('id', b.device_id).eq('owner_id', user.id).select('id').maybeSingle();
      if (error) return err('Falha ao revogar dispositivo', 500);
      return data ? json({ ok: true }) : err('Dispositivo nao encontrado', 404);
    }
    return err('Acao desconhecida', 404);
  } catch (_) {
    return err('Requisicao invalida ou erro interno', 400);
  }
});
