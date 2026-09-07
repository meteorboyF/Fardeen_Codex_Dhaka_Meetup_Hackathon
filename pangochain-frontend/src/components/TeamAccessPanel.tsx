import { useState, useEffect } from 'react'
import { Users, Plus, Trash2, Shield, Lock, Loader2, AlertCircle, Key, Clock } from 'lucide-react'
import api from '../lib/api'
import { eciesUnwrapKey, eciesWrapKey, attestKeyHash, loadWrappedPrivateKey, unwrapPrivateKey } from '../lib/crypto'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'

interface AccessEntry {
  id: string
  userId: string
  userEmail: string
  userFullName: string
  capability: string
  grantedAt: string
  expiresAt: string | null
  revokedAt: string | null
}

interface Candidate {
  id: string
  fullName: string
  email: string
  role: string
  hasPublicKey: boolean
}

interface Props {
  docId: string
  docName: string
}

const CAPABILITY_COLORS: Record<string, string> = {
  owner: 'bg-[#C9A84C]/10 text-[#C9A84C]',
  write: 'bg-blue-50 text-blue-700',
  read:  'bg-emerald-50 text-emerald-700',
}

export function TeamAccessPanel({ docId, docName }: Props) {
  const { user } = useAuthStore()
  const [entries, setEntries] = useState<AccessEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showGrant, setShowGrant] = useState(false)
  const [grantEmail, setGrantEmail] = useState('')
  const [grantCap, setGrantCap] = useState<'read' | 'write'>('read')
  const [grantExpiry, setGrantExpiry] = useState('')
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null)
  const [unlocking, setUnlocking] = useState(false)
  const [granting, setGranting] = useState(false)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [candidates, setCandidates] = useState<Candidate[]>([])
  const [loadingCandidates, setLoadingCandidates] = useState(false)

  useEffect(() => { loadAccess() }, [docId])

  useEffect(() => {
    if (!showGrant) return
    const t = setTimeout(async () => {
      setLoadingCandidates(true)
      try {
        const { data } = await api.get<Candidate[]>('/users/access-candidates', {
          params: { docId, q: grantEmail.trim() },
        })
        setCandidates(data ?? [])
      } catch {
        setCandidates([])
      } finally {
        setLoadingCandidates(false)
      }
    }, 200)
    return () => clearTimeout(t)
  }, [showGrant, grantEmail, docId])

  async function loadAccess() {
    setLoading(true)
    setError('')
    try {
      const { data } = await api.get(`/access/${docId}`)
      setEntries(data ?? [])
    } catch (e: any) {
      setError('Failed to load access list')
    } finally {
      setLoading(false)
    }
  }

  const handleUnlock = async () => {
    if (!user || !password) return
    setUnlocking(true)
    try {
      const stored = loadWrappedPrivateKey(user.id)
      if (!stored) throw new Error('No private key on this device')
      const unlocked = await unwrapPrivateKey(password, stored.saltB64, stored.ivB64, stored.encryptedB64)
      setPrivateKey(unlocked)
      toast.success('Private key unlocked')
    } catch {
      toast.error('Wrong password or no private key on this device')
    } finally {
      setUnlocking(false)
    }
  }

  const handleGrant = async () => {
    if (!grantEmail.trim() || !user) return
    if (!privateKey) {
      toast.error('Unlock your private key before granting access')
      return
    }
    setGranting(true)
    try {
      const recipRes = await api.get('/users/by-email', { params: { email: grantEmail.trim() } })
      const recipient = recipRes.data
      if (!recipient.hasPublicKey) {
        toast.error('Recipient has no public key — they must log in once first')
        return
      }

      const pkRes = await api.get(`/users/${recipient.id}/public-key`)
      const recipientPubKeyString: string = pkRes.data.publicKeyJwk
      const recipientPubKey: JsonWebKey = JSON.parse(recipientPubKeyString)
      // Attest the exact JWK string this wrap is produced under (audit finding S4).
      const recipientKeyHash = await attestKeyHash(recipientPubKeyString)

      const { data: myWrappedKeyToken } = await api.get(`/documents/${docId}/wrapped-key`)
      const docKeyB64 = await eciesUnwrapKey(privateKey, myWrappedKeyToken, user?.id)
      const wrappedKeyToken = await eciesWrapKey(recipientPubKey, docKeyB64, recipient.id)

      await api.post('/access/grant', {
        docId,
        granteeId: recipient.id,
        capability: grantCap,
        expiresAtEpochMs: grantExpiry ? new Date(grantExpiry).getTime() : null,
        wrappedKeyToken,
        recipientKeyHash,
      })

      toast.success(`Access granted to ${recipient.email}`)
      setEntries((prev) => [
        ...prev,
        {
          id: `optimistic-${recipient.id}`,
          userId: recipient.id,
          userEmail: recipient.email,
          userFullName: recipient.fullName,
          capability: grantCap,
          grantedAt: new Date().toISOString(),
          expiresAt: grantExpiry ? new Date(grantExpiry).toISOString() : null,
          revokedAt: null,
        },
      ])
      setGrantEmail('')
      setGrantExpiry('')
      setShowGrant(false)
      loadAccess()
    } catch (e: any) {
      toast.error(e.response?.data?.detail ?? 'Failed to grant access')
    } finally {
      setGranting(false)
    }
  }

  const handleRevoke = async (accessUserId: string, email: string) => {
    setRevoking(accessUserId)
    try {
      await api.delete(`/access/${docId}/user/${accessUserId}`)
      toast.success(`Access revoked for ${email}`)
      setEntries((prev) => prev.filter((e) => e.userId !== accessUserId))
    } catch (e: any) {
      toast.error('Failed to revoke access')
    } finally {
      setRevoking(null)
    }
  }

  const active = entries.filter((e) => !e.revokedAt)
  const revoked = entries.filter((e) => e.revokedAt)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-heading font-semibold text-text-primary flex items-center gap-2 text-sm">
          <Users className="w-4 h-4 text-[#C9A84C]" /> Team Access — {docName}
        </h3>
        <button onClick={() => setShowGrant(!showGrant)} className="btn-primary text-xs py-1.5 px-3">
          <Plus className="w-3.5 h-3.5" /> Grant Access
        </button>
      </div>

      {showGrant && (
        <div className="bg-[#C9A84C]/5 border border-[#C9A84C]/20 rounded-xl p-4 space-y-3">
          <p className="text-xs font-semibold text-[#C9A84C] flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" /> Grant Encrypted Access
          </p>
          {!privateKey ? (
            <div className="bg-amber-500/10 border border-amber-500/25 rounded-xl p-3 space-y-2">
              <label className="label text-xs flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5" /> Your Account Password
              </label>
              <div className="flex gap-2">
                <input
                  type="password"
                  className="input text-sm py-2 flex-1"
                  placeholder="Unlock your private key"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
                />
                <button onClick={handleUnlock} disabled={unlocking || !password} className="btn-primary text-xs px-3 disabled:opacity-50">
                  {unlocking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Unlock'}
                </button>
              </div>
              <p className="text-[11px] text-text-muted">Used only in this browser to unwrap and re-wrap the document key.</p>
            </div>
          ) : (
            <div className="text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 rounded-lg px-3 py-2">
              Private key unlocked. Grants will use real ECIES key wrapping.
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="label text-xs">Team Member Email</label>
              <input className="input text-sm py-2" placeholder="associate@firm.com" value={grantEmail} onChange={(e) => setGrantEmail(e.target.value)} />
              <div className="mt-2 rounded-xl border border-gold-500/10 bg-navy-950/40 overflow-hidden">
                {loadingCandidates ? (
                  <div className="px-3 py-2 text-[11px] text-text-muted flex items-center gap-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Searching eligible users...
                  </div>
                ) : candidates.length > 0 ? candidates.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setGrantEmail(c.email)}
                    className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-gold-500/10 border-b border-gold-500/5 last:border-b-0"
                  >
                    <span className="w-6 h-6 rounded-full bg-gold-500/10 border border-gold-500/20 flex items-center justify-center text-[10px] font-bold text-gold-300">
                      {c.fullName?.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase() || '?'}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-xs text-text-primary truncate">{c.fullName}</span>
                      <span className="block text-[10px] text-text-muted truncate">{c.email} · {c.role.replace(/_/g, ' ')}</span>
                    </span>
                    {!c.hasPublicKey && <span className="text-[9px] text-gold-400">needs login</span>}
                  </button>
                )) : (
                  <div className="px-3 py-2 text-[11px] text-text-muted">No eligible users without access.</div>
                )}
              </div>
            </div>
            <div>
              <label className="label text-xs">Permission Level</label>
              <select className="input text-sm py-2" value={grantCap} onChange={(e) => setGrantCap(e.target.value as any)}>
                <option value="read">Read only</option>
                <option value="write">Read + Write</option>
              </select>
            </div>
          </div>
          <div>
            <label className="label text-xs">Access Expires (optional)</label>
            <input type="datetime-local" className="input text-sm py-2" value={grantExpiry} onChange={(e) => setGrantExpiry(e.target.value)} />
          </div>
          <div className="flex gap-2">
            <button onClick={() => setShowGrant(false)} className="btn border border-border text-text-secondary text-xs py-1.5 px-3">Cancel</button>
            <button
              onClick={handleGrant}
              disabled={granting || !grantEmail.trim() || !privateKey}
              className="btn-primary text-xs py-1.5 px-3 disabled:opacity-50"
            >
              {granting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Granting…</> : <><Lock className="w-3.5 h-3.5" /> Grant Access</>}
            </button>
          </div>
        </div>
      )}

      {loading && <div className="flex justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-[#C9A84C]" /></div>}
      {error && <div className="flex items-center gap-2 text-xs text-error bg-red-50 border border-red-200 rounded-lg px-3 py-2"><AlertCircle className="w-3.5 h-3.5" /> {error}</div>}

      {!loading && !error && (
        <div className="space-y-2">
          {active.map((e) => (
            <div key={e.id} className="flex items-center gap-3 bg-surface-muted rounded-xl px-4 py-3">
              <div className="w-8 h-8 rounded-full bg-[#C9A84C]/10 flex items-center justify-center text-xs font-bold text-[#C9A84C]">
                {e.userFullName?.[0]?.toUpperCase() ?? '?'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-text-primary truncate">{e.userFullName || e.userEmail}</p>
                <p className="text-xs text-text-muted">{e.userEmail}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${CAPABILITY_COLORS[e.capability.toLowerCase()] ?? ''}`}>
                  {e.capability.toLowerCase()}
                </span>
                {e.expiresAt && (
                  <span className="text-[10px] text-text-muted flex items-center gap-0.5">
                    <Clock className="w-3 h-3" />
                    {new Date(e.expiresAt).toLocaleDateString()}
                  </span>
                )}
                {e.capability.toLowerCase() !== 'owner' && (
                  <button
                    onClick={() => handleRevoke(e.userId, e.userEmail)}
                    disabled={revoking === e.userId}
                    className="p-1.5 rounded-lg hover:bg-red-50 text-text-muted hover:text-error transition-colors"
                    title="Revoke access"
                  >
                    {revoking === e.userId
                      ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      : <Trash2 className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
            </div>
          ))}

          {active.length === 0 && (
            <p className="text-sm text-text-muted text-center py-4">No active access grants</p>
          )}

          {revoked.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] font-semibold text-text-muted uppercase tracking-wide mb-2">Revoked</p>
              {revoked.slice(0, 3).map((e) => (
                <div key={e.id} className="flex items-center gap-3 px-4 py-2 opacity-50">
                  <div className="w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center text-[10px] font-bold text-gray-500">
                    {e.userFullName?.[0]?.toUpperCase() ?? '?'}
                  </div>
                  <p className="text-xs text-text-muted truncate">{e.userEmail}</p>
                  <span className="text-[10px] bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded ml-auto">revoked</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
