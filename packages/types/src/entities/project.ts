/**
 * Represents a registered software project configured for VibeShield security scans.
 */
export interface Project {
  /**
   * Unique identifier of the project.
   */
  id: string;

  /**
   * Human-readable project or repository name.
   */
  name: string;

  /**
   * Remote repository URL (e.g. GitHub/GitLab repository URL).
   */
  repositoryUrl: string;

  /**
   * Default branch to scan (e.g., 'main' or 'master').
   */
  defaultBranch: string;

  /**
   * Timestamp when the project was registered.
   */
  createdAt: Date | string;

  /**
   * Timestamp when the project settings were last updated.
   */
  updatedAt: Date | string;
}
