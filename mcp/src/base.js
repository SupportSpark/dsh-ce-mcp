#!/usr/bin/env node
// -*- coding: utf-8 -*-
/**
 * Cheat Engine MCP Server - Named pipe bridge to Cheat Engine
 * JavaScript/Node.js version
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

// ============ Configuration ============
const Config = {
  PIPE_NAME: '\\\\.\\pipe\\ce_mcp_bridge',
  MAX_RETRIES: 3,
  CHUNK_SIZE: 1024 * 1024,
  MAX_RESPONSE_SIZE: 10 * 1024 * 1024,
  DEBUG: false,
};

// ============ Timeout Error ============
class TimeoutError extends Error {
  constructor(toolName, params, elapsedTime, timeout) {
    super(`Tool '${toolName}' timed out after ${elapsedTime.toFixed(2)}s (timeout: ${timeout}s)`);
    this.toolName = toolName;
    this.params = params;
    this.elapsedTime = elapsedTime;
    this.timeout = timeout;
  }
}

// ============ Logger ============
class Logger {
  static log(msg, level = 'INFO') {
    if (level === 'DEBUG' && !Config.DEBUG) return;
    process.stderr.write(`[CheatEngine-MCP-${level}] ${msg}\n`);
  }

  static info(msg) {
    Logger.log(msg, 'INFO');
  }

  static debug(msg) {
    Logger.log(msg, 'DEBUG');
  }

  static error(msg) {
    Logger.log(msg, 'ERROR');
  }
}

const log = Logger;

// ============ Connection Health Monitoring ============
class ConnectionHealth {
  constructor() {
    this.lastSuccessTime = 0.0;
    this.connectionAttempts = 0;
    this.consecutiveErrors = 0;
    this.totalErrors = 0;
    this.lastError = null;
    this.isConnected = false;
  }
}

class HealthMonitor {
  constructor(errorThreshold = 5) {
    this.health = new ConnectionHealth();
    this.errorThreshold = errorThreshold;
  }

  recordSuccess() {
    this.health.lastSuccessTime = Date.now() / 1000;
    this.health.consecutiveErrors = 0;
    this.health.isConnected = true;
  }

  recordError(error) {
    this.health.consecutiveErrors++;
    this.health.totalErrors++;
    this.health.lastError = error;
    this.health.isConnected = false;
    return this.health.consecutiveErrors >= this.errorThreshold;
  }

  recordConnectionAttempt() {
    this.health.connectionAttempts++;
  }

  getMetrics() {
    return {
      last_success_time: this.health.lastSuccessTime,
      connection_attempts: this.health.connectionAttempts,
      consecutive_errors: this.health.consecutiveErrors,
      total_errors: this.health.totalErrors,
      last_error: this.health.lastError,
      is_connected: this.health.isConnected,
    };
  }

  reset() {
    this.health = new ConnectionHealth();
  }
}

// ============ Timeout Manager ============
class TimeoutManager {
  static DEFAULT_TIMEOUT = 30;

  static TOOL_TIMEOUTS = {
    ce_find_pointer_path: 60,
    ce_break_and_trace: 60,
    ce_find_what_accesses: 60,
    ce_find_what_writes: 60,
    ce_aob_scan: 30,
    ce_value_scan: 30,
    ce_scan_new: 30,
    ce_scan_next: 30,
    ce_build_cfg: 45,
    ce_symbolic_trace: 45,
    ce_call_function: 30,
    ce_get_process_info: 120,
    ce_get_symbol: 120,
    ce_trace_struct_access: 30,
    ce_hook_function: 30,
  };

  constructor(defaultTimeout = null, toolTimeouts = null) {
    this.defaultTimeout = defaultTimeout !== null ? defaultTimeout : TimeoutManager.DEFAULT_TIMEOUT;
    this.toolTimeouts = { ...TimeoutManager.TOOL_TIMEOUTS };
    if (toolTimeouts) {
      Object.assign(this.toolTimeouts, toolTimeouts);
    }
  }

  getTimeout(toolName) {
    return this.toolTimeouts[toolName] || this.defaultTimeout;
  }

  setTimeout(toolName, timeout) {
    this.toolTimeouts[toolName] = timeout;
  }

  getAllTimeouts() {
    return {
      default_timeout: this.defaultTimeout,
      tool_timeouts: { ...this.toolTimeouts },
    };
  }
}

// ============ Metrics Collector ============
class ToolMetrics {
  constructor() {
    this.callCount = 0;
    this.totalTime = 0.0;
    this.errorCount = 0;
    this.lastCallTime = 0.0;
  }
}

class MetricsCollector {
  constructor() {
    this.toolMetrics = new Map();
    this.startTime = Date.now() / 1000;
  }

  recordCall(toolName, duration, isError = false) {
    if (!this.toolMetrics.has(toolName)) {
      this.toolMetrics.set(toolName, new ToolMetrics());
    }

    const metrics = this.toolMetrics.get(toolName);
    metrics.callCount++;
    metrics.totalTime += duration;
    metrics.lastCallTime = Date.now() / 1000;
    if (isError) {
      metrics.errorCount++;
    }
  }

  getToolMetrics(toolName) {
    const metrics = this.toolMetrics.get(toolName);
    if (!metrics) return null;

    return {
      calls: metrics.callCount,
      total_time: metrics.totalTime,
      avg_time: metrics.callCount > 0 ? metrics.totalTime / metrics.callCount : 0,
      errors: metrics.errorCount,
      error_rate: metrics.callCount > 0 ? metrics.errorCount / metrics.callCount : 0,
      last_call_time: metrics.lastCallTime,
    };
  }

  getSummary() {
    let totalCalls = 0;
    let totalErrors = 0;
    const tools = {};

    for (const [name, metrics] of this.toolMetrics) {
      totalCalls += metrics.callCount;
      totalErrors += metrics.errorCount;
      tools[name] = {
        calls: metrics.callCount,
        avg_time: metrics.callCount > 0 ? metrics.totalTime / metrics.callCount : 0,
        errors: metrics.errorCount,
        error_rate: metrics.callCount > 0 ? metrics.errorCount / metrics.callCount : 0,
      };
    }

    return {
      uptime: Date.now() / 1000 - this.startTime,
      total_calls: totalCalls,
      total_errors: totalErrors,
      error_rate: totalCalls > 0 ? totalErrors / totalCalls : 0,
      tools,
    };
  }

  reset() {
    this.toolMetrics.clear();
    this.startTime = Date.now() / 1000;
  }
}

module.exports = {
  Config,
  TimeoutError,
  ConnectionHealth,
  HealthMonitor,
  TimeoutManager,
  ToolMetrics,
  MetricsCollector,
  Logger,
  log,
};
