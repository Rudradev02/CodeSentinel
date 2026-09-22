"""Repository catalog service managing registered codebases."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.security import validate_repository_path
from backend.app.models.repository import Repository


class RepositoryStore:
    """Data access and lifecycle operations for registered repositories."""

    @staticmethod
    async def register_repository(
        db: AsyncSession,
        path_str: str,
        name: Optional[str] = None,
    ) -> tuple[Repository, bool]:
        """Register a new repository or return existing if path is already registered.
        
        Args:
            db: Async database session.
            path_str: Unvalidated repository path string.
            name: Optional display name (defaults to directory name).
            
        Returns:
            Tuple of (Repository, created_flag).
        """
        # 1. Enforce local filesystem security boundary
        canonical_path: Path = validate_repository_path(path_str)
        canonical_path_str = str(canonical_path)

        # 2. Check if already registered
        query = (
            select(Repository)
            .where(Repository.path == canonical_path_str)
            .options(selectinload(Repository.analyses))
        )
        result = await db.execute(query)
        existing = result.scalar_one_or_none()

        if existing is not None:
            if name and existing.name != name:
                existing.name = name
                existing.updated_at = datetime.now(timezone.utc)
                await db.commit()
                await db.refresh(existing)
            return existing, False

        # 3. Create new repository record
        display_name = name.strip() if name and name.strip() else canonical_path.name
        new_repo = Repository(
            id=str(uuid.uuid4()),
            name=display_name,
            path=canonical_path_str,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(new_repo)
        await db.commit()
        # Eagerly load analyses on the newly committed repository
        fresh_repo = await RepositoryStore.get_repository(db, new_repo.id)
        return fresh_repo or new_repo, True

    @staticmethod
    async def get_repository(db: AsyncSession, repo_id: str) -> Optional[Repository]:
        """Fetch a single registered repository by its UUID with analyses preloaded."""
        query = (
            select(Repository)
            .where(Repository.id == repo_id)
            .options(selectinload(Repository.analyses))
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_repository_by_path(db: AsyncSession, path_str: str) -> Optional[Repository]:
        """Fetch a registered repository by its canonical path string."""
        query = (
            select(Repository)
            .where(Repository.path == path_str)
            .options(selectinload(Repository.analyses))
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_repositories(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Repository], int]:
        """List registered repositories with pagination, ordered by updated_at descending."""
        # Total count
        count_query = select(func.count(Repository.id))
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        # Paginated items
        items_query = (
            select(Repository)
            .options(selectinload(Repository.analyses))
            .order_by(Repository.updated_at.desc())
            .offset(skip)
            .limit(limit)
        )
        items_result = await db.execute(items_query)
        repositories = list(items_result.scalars().all())

        return repositories, total

    @staticmethod
    async def delete_repository(db: AsyncSession, repo_id: str) -> bool:
        """Unregister a repository, cascading deletion of all associated historical analyses."""
        repo = await RepositoryStore.get_repository(db, repo_id)
        if repo is None:
            return False

        await db.delete(repo)
        await db.commit()
        return True
