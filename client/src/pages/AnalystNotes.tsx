import { GlassPanel, ThreatBadge } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { trpc } from "@/lib/trpc";
import { Plus, StickyNote, CheckCircle, Trash2 } from "lucide-react";
import { useCallback, useState } from "react";
import { toast } from "sonner";

type Severity = "critical" | "high" | "medium" | "low" | "info";

export default function AnalystNotes() {
  const [open, setOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const utils = trpc.useUtils();

  // Form state
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [severity, setSeverity] = useState<Severity>("info");
  const [agentId, setAgentId] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [cveId, setCveId] = useState("");

  const notesQ = trpc.hybridrag.notes.list.useQuery(
    {
      severity: severityFilter !== "all" ? (severityFilter as Severity) : undefined,
      limit: 100,
    },
    { staleTime: 10_000 }
  );

  const createMut = trpc.hybridrag.notes.create.useMutation({
    onSuccess: () => {
      utils.hybridrag.notes.list.invalidate();
      setOpen(false);
      resetForm();
      toast.success("Note created");
    },
    onError: (err) => toast.error(err.message),
  });

  const updateMut = trpc.hybridrag.notes.update.useMutation({
    onSuccess: () => {
      utils.hybridrag.notes.list.invalidate();
      toast.success("Note updated");
    },
  });

  const deleteMut = trpc.hybridrag.notes.delete.useMutation({
    onSuccess: () => {
      utils.hybridrag.notes.list.invalidate();
      toast.success("Note deleted");
    },
  });

  const handleRefresh = useCallback(() => {
    utils.hybridrag.notes.list.invalidate();
  }, [utils]);

  const resetForm = () => {
    setTitle("");
    setContent("");
    setSeverity("info");
    setAgentId("");
    setRuleId("");
    setCveId("");
  };

  const handleCreate = () => {
    if (!title.trim()) {
      toast.error("Title is required");
      return;
    }
    createMut.mutate({
      title: title.trim(),
      content,
      severity,
      agentId: agentId || undefined,
      ruleId: ruleId || undefined,
      cveId: cveId || undefined,
      tags: [],
    });
  };

  const notes = notesQ.data?.notes ?? [];

  return (
    <div>
      <PageHeader
        title="Analyst Notes"
        subtitle="Local forensic annotations — never written to Wazuh"
        onRefresh={handleRefresh}
        isLoading={notesQ.isLoading}
      >
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="h-8 bg-primary hover:bg-primary/90 text-primary-foreground gap-1.5">
              <Plus className="h-3.5 w-3.5" />
              New Note
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader>
              <DialogTitle className="font-display text-foreground">Create Analyst Note</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div>
                <Label className="text-xs text-muted-foreground">Title *</Label>
                <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Incident summary..." className="mt-1 bg-secondary/50 border-border" />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Content</Label>
                <Textarea value={content} onChange={(e) => setContent(e.target.value)} placeholder="Detailed notes (Markdown supported)..." className="mt-1 bg-secondary/50 border-border min-h-[120px] font-mono text-xs" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs text-muted-foreground">Severity</Label>
                  <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                    <SelectTrigger className="mt-1 bg-secondary/50 border-border"><SelectValue /></SelectTrigger>
                    <SelectContent className="bg-popover border-border">
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="info">Info</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Agent ID</Label>
                  <Input value={agentId} onChange={(e) => setAgentId(e.target.value)} placeholder="000" className="mt-1 bg-secondary/50 border-border font-mono" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs text-muted-foreground">Rule ID</Label>
                  <Input value={ruleId} onChange={(e) => setRuleId(e.target.value)} placeholder="e.g. 550" className="mt-1 bg-secondary/50 border-border font-mono" />
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">CVE ID</Label>
                  <Input value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2024-..." className="mt-1 bg-secondary/50 border-border font-mono" />
                </div>
              </div>
              <Button onClick={handleCreate} disabled={createMut.isPending} className="w-full bg-primary hover:bg-primary/90 text-primary-foreground">
                {createMut.isPending ? "Creating..." : "Create Note"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </PageHeader>

      {/* ── Filter ────────────────────────────────────────── */}
      <div className="flex items-center gap-3 mb-6">
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[130px] h-8 text-xs bg-secondary/50 border-border"><SelectValue /></SelectTrigger>
          <SelectContent className="bg-popover border-border">
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground">{notes.length} notes</span>
      </div>

      {/* ── Notes list ────────────────────────────────────── */}
      <div className="space-y-3">
        {notes.map((note) => (
          <GlassPanel key={note.id} className="p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <ThreatBadge level={note.severity as Severity} />
                  {note.resolved === 1 && (
                    <span className="inline-flex items-center gap-1 text-[10px] text-[oklch(0.765_0.177_163.223)]">
                      <CheckCircle className="h-3 w-3" /> Resolved
                    </span>
                  )}
                </div>
                <h3 className="font-display font-semibold text-foreground text-sm">{note.title}</h3>
                {note.content && (
                  <p className="text-xs text-muted-foreground mt-1 whitespace-pre-wrap font-mono line-clamp-4">
                    {note.content}
                  </p>
                )}
                <div className="flex flex-wrap gap-3 mt-2 text-[10px] text-muted-foreground">
                  {note.agentId && <span>Agent: <span className="text-primary font-mono">{note.agentId}</span></span>}
                  {note.ruleId && <span>Rule: <span className="text-primary font-mono">{note.ruleId}</span></span>}
                  {note.cveId && <span>CVE: <span className="text-primary font-mono">{note.cveId}</span></span>}
                  <span className="font-mono">{new Date(note.createdAt).toLocaleString()}</span>
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                {note.resolved === 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => updateMut.mutate({ id: note.id, resolved: true })}
                    className="h-7 text-xs bg-transparent border-border gap-1"
                  >
                    <CheckCircle className="h-3 w-3" /> Resolve
                  </Button>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    if (confirm("Delete this note?")) deleteMut.mutate({ id: note.id });
                  }}
                  className="h-7 w-7 p-0 bg-transparent border-border text-destructive hover:text-destructive"
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            </div>
          </GlassPanel>
        ))}
        {notes.length === 0 && (
          <GlassPanel className="p-12 text-center">
            <StickyNote className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              {notesQ.isLoading ? "Loading notes..." : "No analyst notes yet. Create one to start documenting findings."}
            </p>
          </GlassPanel>
        )}
      </div>
    </div>
  );
}
