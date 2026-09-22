import React, { useEffect, useState } from 'react';
import {
  FolderGit2,
  Plus,
  Trash2,
  Check,
  Loader2,
  Clock,
} from 'lucide-react';
import {
  deleteRepository,
  listRepositories,
  registerRepository,
} from '../../api/client';
import { RepositoryDTO } from '../../types';

interface RepositorySelectorProps {
  selectedRepo: RepositoryDTO | null;
  onSelectRepo: (repo: RepositoryDTO | null) => void;
  onOpenHistory: () => void;
}

export const RepositorySelector: React.FC<RepositorySelectorProps> = ({
  selectedRepo,
  onSelectRepo,
  onOpenHistory,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [repositories, setRepositories] = useState<RepositoryDTO[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newPath, setNewPath] = useState('');
  const [newName, setNewName] = useState('');
  const [addError, setAddError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const fetchRepos = async () => {
    setLoading(true);
    try {
      const data = await listRepositories(0, 100);
      setRepositories(data.items);
      if (!selectedRepo && data.items.length > 0) {
        onSelectRepo(data.items[0]);
      }
    } catch {
      // Backend might not have repos yet
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRepos();
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPath.trim()) return;

    setSubmitting(true);
    setAddError(null);

    try {
      const repo = await registerRepository(newPath.trim(), newName.trim() || undefined);
      setRepositories((prev) => [repo, ...prev.filter((r) => r.id !== repo.id)]);
      onSelectRepo(repo);
      setNewPath('');
      setNewName('');
      setShowAddForm(false);
      setIsOpen(false);
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to register repository.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (e: React.MouseEvent, repoId: string) => {
    e.stopPropagation();
    if (!confirm('Unregister this repository and delete its historical snapshots?')) return;

    try {
      await deleteRepository(repoId);
      setRepositories((prev) => prev.filter((r) => r.id !== repoId));
      if (selectedRepo?.id === repoId) {
        const remaining = repositories.filter((r) => r.id !== repoId);
        onSelectRepo(remaining.length > 0 ? remaining[0] : null);
      }
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete repository');
    }
  };

  return (
    <div className="relative">
      <div className="flex items-center space-x-1.5">
        <button
          onClick={() => {
            setIsOpen(!isOpen);
            if (!isOpen) fetchRepos();
          }}
          className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/90 hover:bg-slate-700/90 border border-slate-700/70 transition-all max-w-xs truncate"
          title={selectedRepo ? selectedRepo.path : 'Select or Register Repository'}
        >
          <FolderGit2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span className="truncate">
            {selectedRepo ? selectedRepo.name : 'Select Repository'}
          </span>
          {selectedRepo && (
            <span className="px-1.5 py-0.2 rounded bg-slate-900 text-emerald-400 font-mono text-[10px] border border-slate-700 shrink-0">
              {selectedRepo.analysis_count}
            </span>
          )}
        </button>

        {selectedRepo && (
          <button
            onClick={onOpenHistory}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/90 hover:bg-slate-700/90 border border-slate-700/70 transition-all"
            title="View Immutable Analysis History"
          >
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>History</span>
          </button>
        )}
      </div>

      {isOpen && (
        <div className="absolute left-0 mt-2 w-96 rounded-xl bg-[#141B2B] border border-slate-700 shadow-2xl z-50 overflow-hidden">
          <div className="p-3 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">Repository Catalog</span>
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="inline-flex items-center space-x-1 text-[11px] text-emerald-400 hover:text-emerald-300 font-medium transition-colors"
            >
              <Plus className="w-3 h-3" />
              <span>Register New</span>
            </button>
          </div>

          {showAddForm && (
            <form onSubmit={handleRegister} className="p-3 border-b border-slate-800 bg-[#0E1420] space-y-2.5">
              <div className="text-[11px] font-semibold text-emerald-400">Register Local Repository</div>
              <input
                type="text"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
                placeholder="Filesystem path (e.g. tests/fixtures/sample_project)..."
                className="w-full bg-[#182234] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
              />
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Display Name (optional)"
                className="w-full bg-[#182234] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              {addError && (
                <div className="text-[11px] text-rose-400 bg-rose-950/40 p-1.5 rounded border border-rose-900/60">
                  {addError}
                </div>
              )}
              <div className="flex justify-end space-x-2 pt-1">
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="px-2.5 py-1 rounded text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !newPath.trim()}
                  className="px-3 py-1 rounded text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50 inline-flex items-center space-x-1.5"
                >
                  {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
                  <span>Register</span>
                </button>
              </div>
            </form>
          )}

          <div className="max-h-64 overflow-y-auto divide-y divide-slate-800/60">
            {loading ? (
              <div className="p-4 flex items-center justify-center space-x-2 text-xs text-slate-400">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                <span>Loading repositories...</span>
              </div>
            ) : repositories.length === 0 ? (
              <div className="p-4 text-center text-xs text-slate-500">
                No repositories registered yet.
              </div>
            ) : (
              repositories.map((repo) => {
                const isSelected = selectedRepo?.id === repo.id;
                return (
                  <div
                    key={repo.id}
                    onClick={() => {
                      onSelectRepo(repo);
                      setIsOpen(false);
                    }}
                    className={`p-3 flex items-start justify-between space-x-3 cursor-pointer transition-colors ${
                      isSelected ? 'bg-emerald-950/20 text-white' : 'hover:bg-slate-800/50 text-slate-300'
                    }`}
                  >
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-xs text-slate-100 truncate">{repo.name}</span>
                        {isSelected && <Check className="w-3 h-3 text-emerald-400 shrink-0" />}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono truncate" title={repo.path}>
                        {repo.path}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">
                        {repo.analysis_count} runs
                      </span>
                      <button
                        onClick={(e) => handleDelete(e, repo.id)}
                        className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                        title="Unregister repository"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
};
