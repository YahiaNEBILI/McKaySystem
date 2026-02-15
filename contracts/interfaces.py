"""
Protocol definitions for dependency injection.

This module defines explicit interfaces (Protocols) for all external dependencies,
enabling:
- Easy mocking in tests
- Clear contracts between components
- Better AI understanding of dependencies

Usage:
    from contracts.interfaces import EC2ClientProtocol, S3ClientProtocol

    # In production, use real boto3 clients
    # In tests, use unittest.mock or moto
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, Protocol, runtime_checkable

# -----------------------------------------------------------------------------
# AWS Service Protocols
# -----------------------------------------------------------------------------

@runtime_checkable
class EC2ClientProtocol(Protocol):
    """Protocol for EC2 client interactions."""

    def describe_instances(self, *, Filters: list[dict[str, Any]] | None = None,
                          InstanceIds: list[str] | None = None,
                          MaxResults: int | None = None,
                          NextToken: str | None = None) -> dict[str, Any]:
        """Describe EC2 instances."""
        ...

    def describe_volumes(self, *, Filters: list[dict[str, Any]] | None = None,
                        VolumeIds: list[str] | None = None,
                        MaxResults: int | None = None,
                        NextToken: str | None = None) -> dict[str, Any]:
        """Describe EBS volumes."""
        ...

    def describe_reserved_instances(self, *, Filters: list[dict[str, Any]] | None = None,
                                   ReservedInstanceIds: list[str] | None = None) -> dict[str, Any]:
        """Describe reserved instances."""
        ...


@runtime_checkable
class RDSClientProtocol(Protocol):
    """Protocol for RDS client interactions."""

    def describe_db_instances(self, *, DBInstanceIdentifier: str | None = None,
                             Filters: list[dict[str, Any]] | None = None,
                             MaxRecords: int | None = None,
                             Marker: str | None = None) -> dict[str, Any]:
        """Describe RDS instances."""
        ...

    def describe_db_snapshots(self, *, DBInstanceIdentifier: str | None = None,
                              DBSnapshotIdentifier: str | None = None,
                              SnapshotType: str | None = None,
                              MaxRecords: int | None = None,
                              Marker: str | None = None) -> dict[str, Any]:
        """Describe RDS snapshots."""
        ...


@runtime_checkable
class S3ClientProtocol(Protocol):
    """Protocol for S3 client interactions."""

    def list_buckets(self) -> dict[str, Any]:
        """List all S3 buckets."""
        ...

    def get_bucket_lifecycle_configuration(self, Bucket: str) -> dict[str, Any]:
        """Get bucket lifecycle configuration."""
        ...

    def get_bucket_encryption(self, Bucket: str) -> dict[str, Any]:
        """Get bucket encryption settings."""
        ...

    def get_bucket_policy(self, Bucket: str) -> dict[str, Any]:
        """Get bucket policy."""
        ...

    def list_objects_v2(self, *, Bucket: str, Prefix: str | None = None,
                       ContinuationToken: str | None = None,
                       MaxKeys: int | None = None) -> dict[str, Any]:
        """List objects in bucket."""
        ...


@runtime_checkable
class BackupClientProtocol(Protocol):
    """Protocol for AWS Backup client interactions."""

    def list_backup_vaults(self, *, MaxResults: int | None = None,
                           NextToken: str | None = None) -> dict[str, Any]:
        """List backup vaults."""
        ...

    def list_backup_plans(self, *, MaxResults: int | None = None,
                          NextToken: str | None = None) -> dict[str, Any]:
        """List backup plans."""
        ...


@runtime_checkable
class LambdaClientProtocol(Protocol):
    """Protocol for Lambda client interactions."""

    def list_functions(self, *, FunctionVersion: str | None = None,
                      Marker: str | None = None,
                      MaxItems: int | None = None) -> dict[str, Any]:
        """List Lambda functions."""
        ...


@runtime_checkable
class CloudWatchClientProtocol(Protocol):
    """Protocol for CloudWatch client interactions."""

    def list_metrics(self, *, Namespace: str | None = None,
                    MetricName: str | None = None,
                    Dimensions: list[dict[str, str]] | None = None,
                    NextToken: str | None = None) -> dict[str, Any]:
        """List CloudWatch metrics."""
        ...

    def get_metric_statistics(self, *, Namespace: str, MetricName: str,
                             StartTime: Any, EndTime: Any, Period: int,
                             Statistics: list[str] | None = None,
                             Unit: str | None = None) -> dict[str, Any]:
        """Get metric statistics."""
        ...


@runtime_checkable
class CostExplorerClientProtocol(Protocol):
    """Protocol for AWS Cost Explorer client interactions."""

    def get_cost_and_usage(self, *, TimePeriod: dict[str, str],
                          Granularity: str,
                          Metrics: list[str],
                          GroupBy: list[dict[str, str]] | None = None,
                          Filter: dict[str, Any] | None = None) -> dict[str, Any]:
        """Get cost and usage data."""
        ...


@runtime_checkable
class PricingClientProtocol(Protocol):
    """Protocol for AWS Pricing client interactions."""

    def get_products(self, *, ServiceCode: str,
                     Filters: list[dict[str, Any]] | None = None,
                     MaxResults: int | None = None,
                     NextToken: str | None = None) -> dict[str, Any]:
        """Get AWS pricing information."""
        ...


# -----------------------------------------------------------------------------
# Storage Protocols
# -----------------------------------------------------------------------------

@runtime_checkable
class ParquetWriterProtocol(Protocol):
    """Protocol for writing Parquet files."""

    def write(self, records: Iterator[dict[str, Any]], schema: Any) -> int:
        """Write records to Parquet, return count."""
        ...

    def close(self) -> None:
        """Close the writer."""
        ...


@runtime_checkable
class DuckDBConnectionProtocol(Protocol):
    """Protocol for DuckDB connections."""

    def execute(self, query: str, parameters: list[Any] | None = None) -> Any:
        """Execute a query."""
        ...

    def execute_many(self, query: str, parameters: list[list[Any]]) -> None:
        """Execute a query many times."""
        ...

    def fetchall(self) -> list[tuple[Any, ...]]:
        """Fetch all results."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


# -----------------------------------------------------------------------------
# Database Protocols
# -----------------------------------------------------------------------------

@runtime_checkable
class PostgresConnectionProtocol(Protocol):
    """Protocol for PostgreSQL connections."""

    def cursor(self) -> Any:
        """Get a cursor."""
        ...

    def commit(self) -> None:
        """Commit the transaction."""
        ...

    def rollback(self) -> None:
        """Rollback the transaction."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


@runtime_checkable
class PostgresPoolProtocol(Protocol):
    """Protocol for PostgreSQL connection pools."""

    def getconn(self) -> PostgresConnectionProtocol:
        """Get a connection from the pool."""
        ...

    def putconn(self, conn: PostgresConnectionProtocol) -> None:
        """Return a connection to the pool."""
        ...

    def closeall(self) -> None:
        """Close all connections."""
        ...


# -----------------------------------------------------------------------------
# Application Service Protocols
# -----------------------------------------------------------------------------

class PricingServiceProtocol(Protocol):
    """Protocol for pricing service."""

    def get_on_demand_price(self, service: str, region: str,
                           instance_type: str) -> float | None:
        """Get on-demand price for an instance."""
        ...

    def get_reserved_instance_price(self, service: str, region: str,
                                   instance_type: str, offering_id: str) -> float | None:
        """Get reserved instance price."""
        ...


class CacheProtocol(Protocol):
    """Protocol for caching layer."""

    def get(self, key: str) -> Any:
        """Get a value from cache."""
        ...

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set a value in cache."""
        ...

    def delete(self, key: str) -> None:
        """Delete a key from cache."""
        ...

    def exists(self, key: str) -> bool:
        """Check if key exists."""
        ...


# -----------------------------------------------------------------------------
# Event/Message Queue Protocols
# -----------------------------------------------------------------------------

class MessageQueueProtocol(Protocol):
    """Protocol for message queue operations."""

    def publish(self, topic: str, message: dict[str, Any]) -> str:
        """Publish a message, return message ID."""
        ...

    def subscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> str:
        """Subscribe to a topic, return subscription ID."""
        ...

    def unsubscribe(self, subscription_id: str) -> None:
        """Unsubscribe from a topic."""
        ...


# -----------------------------------------------------------------------------
# Logger Protocol
# -----------------------------------------------------------------------------

class StructuredLoggerProtocol(Protocol):
    """Protocol for structured logging."""

    def debug(self, event: str, **kwargs: Any) -> None:
        """Log debug message."""
        ...

    def info(self, event: str, **kwargs: Any) -> None:
        """Log info message."""
        ...

    def warning(self, event: str, **kwargs: Any) -> None:
        """Log warning message."""
        ...

    def error(self, event: str, **kwargs: Any) -> None:
        """Log error message."""
        ...

    def critical(self, event: str, **kwargs: Any) -> None:
        """Log critical message."""
        ...
