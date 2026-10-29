/**
 * Windows Named Pipe Client for Cheat Engine MCP Bridge
 * Uses Node.js net module to connect to Windows named pipes
 */

const net = require('net');
const { EventEmitter } = require('events');
const { Config, HealthMonitor, TimeoutError, Logger, log } = require('./base');

// Windows error codes
const ERROR_FILE_NOT_FOUND = 2;
const ERROR_PIPE_BUSY = 231;
const ERROR_ACCESS_DENIED = 5;
const ERROR_BROKEN_PIPE = 109;
const ERROR_PIPE_NOT_CONNECTED = 233;

class PipeClient extends EventEmitter {
  constructor(pipeName = Config.PIPE_NAME, errorThreshold = 5) {
    super();
    this.pipeName = pipeName;
    this.socket = null;
    this.healthMonitor = new HealthMonitor(errorThreshold);
    this.reconnectTimer = null;
    this.reconnectLoopPromise = null;
    this.stopReconnectFlag = false;
    this.connected = false;
    this.connectionAttempts = 0;
    this.lastError = null;
    this.lastConnectErrorCode = null;
    this.lastSuccessTime = 0;
    this.responseBuffer = Buffer.alloc(0);
    this.pendingResponse = null;
  }

  isValid() {
    return this.socket !== null && this.connected && !this.socket.destroyed;
  }

  async _tryConnectOnce() {
    return new Promise((resolve) => {
      try {
        const socket = net.createConnection(this.pipeName, () => {
          this.socket = socket;
          this.connected = true;
          this.lastError = null;
          this.lastConnectErrorCode = null;
          this.lastSuccessTime = Date.now() / 1000;
          log.info('Connected to Cheat Engine Pipe');
          this.healthMonitor.recordSuccess();
          resolve(true);
        });

        socket.on('error', (err) => {
          this.lastConnectErrorCode = err.code;
          this.lastError = err.message;
          
          // Handle specific error codes
          if (err.code === 'ENOENT') {
            this.lastConnectErrorCode = ERROR_FILE_NOT_FOUND;
          } else if (err.code === 'EACCES') {
            this.lastConnectErrorCode = ERROR_ACCESS_DENIED;
          } else if (err.message && err.message.includes('EBUSY')) {
            this.lastConnectErrorCode = ERROR_PIPE_BUSY;
          }
          
          resolve(false);
        });

        socket.on('close', () => {
          this.connected = false;
          if (this.socket) {
            this.socket = null;
          }
        });

        socket.on('data', (data) => {
          this._handleData(data);
        });

      } catch (err) {
        this.lastError = err.message;
        resolve(false);
      }
    });
  }

  _handleData(data) {
    this.responseBuffer = Buffer.concat([this.responseBuffer, data]);

    if (this.responseBuffer.length > Config.MAX_RESPONSE_SIZE + 4) {
      if (this.pendingResponse) {
        this.pendingResponse.reject(new Error(`Response buffer exceeded max size (${Config.MAX_RESPONSE_SIZE} bytes)`));
        this.pendingResponse = null;
      }
      this.responseBuffer = Buffer.alloc(0);
      this._close();
      this.healthMonitor.recordError(`Response buffer overflow`);
      return;
    }

    if (!this.pendingResponse) {
      return;
    }

    while (this.pendingResponse && this.responseBuffer.length >= 4) {
      const respLen = this.responseBuffer.readUInt32LE(0);

      if (respLen === 0 || respLen > Config.MAX_RESPONSE_SIZE) {
        this.pendingResponse.reject(new Error(`Invalid response size: ${respLen}`));
        this.pendingResponse = null;
        this.responseBuffer = Buffer.alloc(0);
        this._close();
        this.healthMonitor.recordError(`Invalid response frame length: ${respLen}`);
        return;
      }

      if (this.responseBuffer.length < 4 + respLen) {
        break;
      }

      const respData = this.responseBuffer.slice(4, 4 + respLen);
      this.responseBuffer = this.responseBuffer.slice(4 + respLen);

      try {
        const result = JSON.parse(respData.toString('utf-8'));
        this.pendingResponse.resolve(result);
      } catch (err) {
        this.pendingResponse.reject(err);
      }
      this.pendingResponse = null;
    }
  }

  async _reconnectLoop() {
    let backoff = 0.5;
    const maxBackoff = 10.0;

    try {
      while (!this.stopReconnectFlag) {
        if (!this.isValid()) {
          this.connectionAttempts++;
          this.healthMonitor.recordConnectionAttempt();

          if (await this._tryConnectOnce()) {
            backoff = 0.5;
          } else {
            backoff = Math.min(backoff * 1.5, maxBackoff);
          }
        } else {
          backoff = 0.5;
        }

        await this._sleep(backoff * 1000);
      }
    } finally {
      this.reconnectLoopPromise = null;
      this.emit('reconnect_stopped');
    }
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  startBackgroundReconnect() {
    if (this.reconnectLoopPromise) return;
    this.stopReconnectFlag = false;
    this.reconnectLoopPromise = this._reconnectLoop();
  }

  async connect(force = false, timeout = 3000) {
    if (!force && this.isValid()) {
      return true;
    }

    // Try immediate connection
    this.connectionAttempts++;
    this.healthMonitor.recordConnectionAttempt();
    if (await this._tryConnectOnce()) {
      return true;
    }

    // Start background reconnect and wait
    this.startBackgroundReconnect();
    
    // Wait for connection with timeout
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      if (this.isValid()) return true;
      await this._sleep(100);
    }
    return false;
  }

  _close() {
    this.connected = false;
    if (this.socket) {
      try {
        this.socket.destroy();
      } catch (err) {
        // Ignore
      }
      this.socket = null;
    }
  }

  _getConnectionErrorMessage(winerrorCode, attempt) {
    const messages = {
      [ERROR_FILE_NOT_FOUND]: (
        "Cheat Engine MCP Bridge not running. " +
        "Steps to fix:\n" +
        "1. Open Cheat Engine\n" +
        "2. Table -> Show Cheat Table Lua Script\n" +
        "3. Load or paste ce_mcp_bridge.lua\n" +
        "4. Click Execute\n" +
        "5. Wait for 'MCP' label to appear in CE toolbar"
      ),
      [ERROR_PIPE_BUSY]: "Pipe busy - another client may be connected. Wait a moment and try again.",
      [ERROR_ACCESS_DENIED]: "Access denied - try running as administrator",
      [ERROR_BROKEN_PIPE]: (
        "Connection lost to Cheat Engine. " +
        "This happens when CE is closed. " +
        "Please restart CE and reload ce_mcp_bridge.lua"
      ),
    };
    
    const baseMsg = messages[winerrorCode] || `Connection failed (error ${winerrorCode})`;
    return `${baseMsg} [attempt ${attempt}/${Config.MAX_RETRIES}]`;
  }

  async _doSendReceive(data) {
    for (let retry = 0; retry < Config.MAX_RETRIES; retry++) {
      const connected = await this.connect(retry > 0);
      if (!connected) {
        if (this.lastConnectErrorCode) {
          return {
            error: this._getConnectionErrorMessage(this.lastConnectErrorCode, retry + 1)
          };
        }
        return {
          error: `Cannot connect to CE (attempt ${retry + 1}/${Config.MAX_RETRIES})`
        };
      }

      try {
        const jsonStr = JSON.stringify(data);
        const jsonBytes = Buffer.from(jsonStr, 'utf-8');
        const lenBuffer = Buffer.alloc(4);
        lenBuffer.writeUInt32LE(jsonBytes.length, 0);

        // Send request as one framed buffer to avoid split-frame races
        this.socket.write(Buffer.concat([lenBuffer, jsonBytes]));

        // Wait for response
        const result = await this._waitForResponse();
        this.lastSuccessTime = Date.now() / 1000;
        this.healthMonitor.recordSuccess();
        return result;

      } catch (err) {
        log.debug(`Pipe error (attempt ${retry + 1}): ${err.message}`);
        this.healthMonitor.recordError(err.message);
        this._close();
        await this._sleep(100 * (retry + 1));
      }
    }

    return { error: this.lastError || "Connection failed after retries" };
  }

  _waitForResponse() {
    return new Promise((resolve, reject) => {
      const socket = this.socket;

      if (this.responseBuffer.length >= 4) {
        const respLen = this.responseBuffer.readUInt32LE(0);
        if (respLen > 0 && respLen <= Config.MAX_RESPONSE_SIZE && this.responseBuffer.length >= 4 + respLen) {
          const respData = this.responseBuffer.slice(4, 4 + respLen);
          this.responseBuffer = this.responseBuffer.slice(4 + respLen);

          try {
            const result = JSON.parse(respData.toString('utf-8'));
            resolve(result);
            return;
          } catch (err) {
            reject(err);
            return;
          }
        }
      }

      this.pendingResponse = { resolve, reject };

      if (socket) {
        socket.once('close', () => {
          if (this.pendingResponse && this.pendingResponse.reject === reject) {
            this.pendingResponse = null;
            reject(new Error('Socket closed while waiting for response'));
          }
        });
      }
    });
  }

  async sendReceive(data, timeout = 30000, toolName = null) {
    const timeoutSeconds = timeout / 1000.0;
    const startTime = Date.now();

    // Create timeout promise
    let timeoutHandle = null;
    const timeoutPromise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        const elapsedTime = (Date.now() - startTime) / 1000;
        const errorMsg = `Tool execution timed out after ${elapsedTime.toFixed(2)}s (timeout: ${timeoutSeconds}s)`;
        log.error(`Timeout: tool=${toolName || 'unknown'}, params=${JSON.stringify(data.params || {})}, elapsed=${elapsedTime.toFixed(2)}s`);
        this.healthMonitor.recordError(errorMsg);
        reject(new TimeoutError(toolName || data.command || 'unknown', data.params || {}, elapsedTime, timeoutSeconds));
      }, timeout);
    });

    try {
      const result = await Promise.race([
        this._doSendReceive(data),
        timeoutPromise
      ]);
      return result;
    } catch (err) {
      if (err instanceof TimeoutError) {
        return {
          error: err.message,
          timeout_info: {
            tool_name: toolName || data.command || 'unknown',
            params: data.params || {},
            elapsed_time: err.elapsedTime,
            timeout_seconds: err.timeout,
          },
        };
      }
      return { error: err.message };
    } finally {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
    }
  }

  getHealthMetrics() {
    return this.healthMonitor.getMetrics();
  }

  stop() {
    this.stopReconnectFlag = true;
    this.reconnectLoopPromise = null;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this._close();
  }
}

module.exports = { PipeClient };
