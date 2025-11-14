const path = require('path');
const fs = require('fs');
const { execFile, spawn, exec } = require('child_process');
const express = require('express');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const SUDO_PASSWORD = process.env.SUDO_PASSWORD || '';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'syharikfw-secret-key-change',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const rootDir = __dirname;
const dataPath = path.join(rootDir, 'data.json');
const firewallBin = path.join(rootDir, 'firewall');
const firewallConf = path.join(rootDir, 'firewall.conf');
let firewallProc = null;

function hasSystemd() {
  return new Promise((resolve) => {
    exec('command -v systemctl >/dev/null 2>&1 && echo yes || echo no', (err, stdout) => {
      resolve((stdout || '').toString().trim() === 'yes');
    });
  });
}

function serviceName(instance) {
  const unit = process.env.SYFW_UNIT || 'syharikfw@';
  const iface = instance && String(instance).trim() ? String(instance).trim() : 'lo';
  return `${unit}${iface}`;
}

const wellKnownPorts = {
  20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  67: 'DHCP-Server', 68: 'DHCP-Client', 69: 'TFTP', 80: 'HTTP', 110: 'POP3',
  123: 'NTP', 137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
  143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 465: 'SMTPS',
  587: 'SMTP-Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
  1521: 'Oracle DB', 2049: 'NFS', 2181: 'Zookeeper', 2379: 'etcd',
  2380: 'etcd-peer', 27017: 'MongoDB', 3000: 'SyFW Web (Dont off)', 3306: 'MySQL',
  3389: 'RDP', 5432: 'PostgreSQL', 56379: 'Redis-Sentinel', 5672: 'RabbitMQ',
  5900: 'VNC', 6379: 'Redis', 8000: 'HTTP-Alt', 8080: 'HTTP-Alt', 9000: 'App',
  9200: 'Elasticsearch', 9300: 'ES-Transport'
};

function readState() {
  try {
    const raw = fs.readFileSync(dataPath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    const state = { ports: [22, 53, 80, 443, 3000], lastUpdateTs: Date.now() };
    fs.writeFileSync(dataPath, JSON.stringify(state, null, 2));
    return state;
  }
}

function writeState(state) {
  fs.writeFileSync(dataPath, JSON.stringify(state, null, 2));
}

function readFirewallPorts() {
  try {
    const raw = fs.readFileSync(firewallConf, 'utf8');
    const customLine = raw.split('\n').find(l => l.trim().startsWith('custom_ports')) || '';
    const defaultLine = raw.split('\n').find(l => l.trim().startsWith('default_ports')) || '';
    const parsePorts = (line) => line.split('=')[1] ? line.split('=')[1].split(',').map(s => s.trim()).filter(Boolean).map(Number) : [];
    const custom = parsePorts(customLine);
    const defaults = parsePorts(defaultLine);
    const merged = Array.from(new Set([...(defaults||[]), ...(custom||[])])).filter(n => Number.isInteger(n)).sort((a,b)=>a-b);
    return merged;
  } catch (e) {
    return null;
  }
}

function readFirewallSettings() {
  try {
    const raw = fs.readFileSync(firewallConf, 'utf8');
    const lines = raw.split('\n');
    const settings = {
      strict_mode: 1,
      allow_dns: 1,
      allow_icmp: 0,
      interface: 'lo'
    };
    
    let inSettings = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[SETTINGS]') {
        inSettings = true;
        continue;
      }
      if (trimmed.startsWith('[')) {
        inSettings = false;
        continue;
      }
      if (inSettings && trimmed.includes('=')) {
        const [key, value] = trimmed.split('=').map(s => s.trim());
        if (key === 'strict_mode') settings.strict_mode = parseInt(value) || 0;
        if (key === 'allow_dns') settings.allow_dns = parseInt(value) || 0;
        if (key === 'allow_icmp') settings.allow_icmp = parseInt(value) || 0;
        if (key === 'interface') settings.interface = value || 'lo';
      }
    }
    return settings;
  } catch (e) {
    return { strict_mode: 1, allow_dns: 1, allow_icmp: 0, interface: 'lo' };
  }
}

function writeFirewallSettings(settings) {
  try {
    const raw = fs.readFileSync(firewallConf, 'utf8');
    const lines = raw.split('\n');
    let result = [];
    let inSettings = false;
    let settingsWritten = false;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      
      if (trimmed === '[SETTINGS]') {
        inSettings = true;
        result.push(line);
        result.push(`strict_mode=${settings.strict_mode || 0}`);
        result.push(`allow_dns=${settings.allow_dns || 0}`);
        result.push(`allow_icmp=${settings.allow_icmp || 0}`);
        result.push(`interface=${settings.interface || 'lo'}`);
        settingsWritten = true;
        continue;
      }
      
      if (trimmed.startsWith('[') && inSettings) {
        inSettings = false;
      }
      
      if (inSettings && !settingsWritten && (trimmed.startsWith('strict_mode=') || 
          trimmed.startsWith('allow_dns=') || trimmed.startsWith('allow_icmp=') || 
          trimmed.startsWith('interface='))) {
        continue;
      }
      
      result.push(line);
    }
    
    if (!settingsWritten) {
      const portsIndex = result.findIndex(l => l.trim().startsWith('[PORTS]'));
      if (portsIndex >= 0) {
        result.splice(portsIndex, 0, '[SETTINGS]', 
          `strict_mode=${settings.strict_mode || 0}`,
          `allow_dns=${settings.allow_dns || 0}`,
          `allow_icmp=${settings.allow_icmp || 0}`,
          `interface=${settings.interface || 'lo'}`,
          '');
      } else {
        result.unshift('[SETTINGS]',
          `strict_mode=${settings.strict_mode || 0}`,
          `allow_dns=${settings.allow_dns || 0}`,
          `allow_icmp=${settings.allow_icmp || 0}`,
          `interface=${settings.interface || 'lo'}`,
          '');
      }
    }
    
    fs.writeFileSync(firewallConf, result.join('\n'));
    return true;
  } catch (e) {
    const content = `[SETTINGS]
strict_mode=${settings.strict_mode || 0}
allow_dns=${settings.allow_dns || 0}
allow_icmp=${settings.allow_icmp || 0}
interface=${settings.interface || 'lo'}

[PORTS]
default_ports=22,53,80,443,3000
custom_ports=
`;
    fs.writeFileSync(firewallConf, content);
    return true;
  }
}

function parsePortRange(rangeStr) {
  const ports = [];
  const parts = rangeStr.split(',').map(s => s.trim());
  
  for (const part of parts) {
    if (part.includes('-')) {
      const [start, end] = part.split('-').map(s => s.trim()).map(Number);
      if (Number.isInteger(start) && Number.isInteger(end) && 
          start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && 
          start <= end) {
        for (let p = start; p <= end; p++) {
          ports.push(p);
        }
      } else {
        throw new Error(`Invalid port range: ${part}`);
      }
    } else {
      const port = Number(part);
      if (Number.isInteger(port) && port >= 1 && port <= 65535) {
        ports.push(port);
      } else {
        throw new Error(`Invalid port: ${part}`);
      }
    }
  }
  
  return ports;
}

function execFirewall(args) {
  return new Promise((resolve, reject) => {
    const needsSudo = args.includes('--add') || args.includes('--del') || args.includes('--run');
    
    if (needsSudo && SUDO_PASSWORD) {
      const sudoCmd = spawn('sudo', ['-S', firewallBin, ...args], { cwd: rootDir });
      let stdout = '';
      let stderr = '';
      
      sudoCmd.stdout.on('data', (data) => { stdout += data.toString(); });
      sudoCmd.stderr.on('data', (data) => { stderr += data.toString(); });
      
      sudoCmd.on('error', (err) => reject(new Error(err.message)));
      
      sudoCmd.on('close', (code) => {
        if (code !== 0) {
          return reject(new Error(stderr || `Process exited with code ${code}`));
        }
        resolve({ stdout, stderr });
      });
      
      sudoCmd.stdin.write(SUDO_PASSWORD + '\n');
      sudoCmd.stdin.end();
    } else {
      const cmd = needsSudo ? 'sudo' : firewallBin;
      const cmdArgs = needsSudo ? [firewallBin, ...args] : args;
      
      execFile(cmd, cmdArgs, { cwd: rootDir }, (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr || err.message));
        resolve({ stdout, stderr });
      });
    }
  });
}

async function getFirewallStatus() {
  try {
    const { stdout } = await execFirewall(['--status']);
    const status = (stdout || '').toString().trim();
    return status === 'ONLINE' ? 'ONLINE' : 'OFFLINE';
  } catch {
    return 'OFFLINE';
  }
}

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    req.session.username = username;
    res.json({ success: true, username });
  } else {
    res.status(401).json({ success: false, error: 'Неверный логин или пароль' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.json({ authenticated: true, username: req.session.username });
  } else {
    res.json({ authenticated: false });
  }
});

function requireAuth(req, res, next) {
  if (req.path.startsWith('/api/auth') || 
      req.path === '/login.html' || 
      req.path.startsWith('/favicon.ico') ||
      req.path.startsWith('/style.css') ||
      req.path === '/') {
    return next();
  }
  if (req.session && req.session.authenticated) {
    return next();
  }
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.redirect('/login.html');
}

app.get('/api/state', async (req, res) => {
  const fileState = readState();
  const fwPorts = readFirewallPorts();
  const status = await getFirewallStatus();
  res.json({
    ports: Array.isArray(fwPorts) ? fwPorts : fileState.ports,
    lastUpdateTs: fileState.lastUpdateTs,
    status
  });
});

app.get('/api/well-known', (req, res) => {
  res.json(wellKnownPorts);
});

app.post('/api/ports', async (req, res) => {
  const portInput = req.body && req.body.port;
  if (!portInput) {
    return res.status(400).json({ error: 'Port is required' });
  }
  
  const status = await getFirewallStatus();
  if (status === 'ONLINE') {
    return res.status(409).json({ error: 'Cannot modify ports while firewall is running' });
  }
  
  try {
    const portsToAdd = parsePortRange(String(portInput));
    
    if (portsToAdd.length === 0) {
      return res.status(400).json({ error: 'No valid ports to add' });
    }
    
    const portsString = portsToAdd.join(',');
    try {
      await execFirewall(['--add', portsString]);
    } catch (e) {
      if (!e.message.includes('already') && !e.message.includes('exists')) {
        for (const port of portsToAdd) {
          try {
            await execFirewall(['--add', String(port)]);
          } catch (err) {
            if (!err.message.includes('already') && !err.message.includes('exists')) {
              console.warn(`Failed to add port ${port}: ${err.message}`);
            }
          }
        }
      }
    }
    
    const state = readState();
    state.lastUpdateTs = Date.now();
    writeState(state);
    const ports = readFirewallPorts() || state.ports;
    res.json({ 
      ports, 
      lastUpdateTs: state.lastUpdateTs, 
      status: await getFirewallStatus(),
      added: portsToAdd.length
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/ports/:port', async (req, res) => {
  const portInput = decodeURIComponent(req.params.port);
  
  const status = await getFirewallStatus();
  if (status === 'ONLINE') {
    return res.status(409).json({ error: 'Cannot modify ports while firewall is running' });
  }
  
  try {
    const portsToDelete = parsePortRange(String(portInput));
    
    if (portsToDelete.length === 0) {
      return res.status(400).json({ error: 'No valid ports to delete' });
    }
    
    const portsString = portsToDelete.join(',');
    try {
      await execFirewall(['--del', portsString]);
    } catch (e) {
      for (const port of portsToDelete) {
        try {
          await execFirewall(['--del', String(port)]);
        } catch (err) {
          if (!err.message.includes('not found') && !err.message.includes('not exist')) {
            console.warn(`Failed to delete port ${port}: ${err.message}`);
          }
        }
      }
    }
    
    const state = readState();
    state.lastUpdateTs = Date.now();
    writeState(state);
    const ports = readFirewallPorts() || state.ports;
    res.json({ 
      ports, 
      lastUpdateTs: state.lastUpdateTs, 
      status: await getFirewallStatus(),
      deleted: portsToDelete.length
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/status', async (req, res) => {
  res.json({ status: await getFirewallStatus() });
});

app.post('/api/firewall/start', async (req, res) => {
  try {
    const currentStatus = await getFirewallStatus();
    if (currentStatus === 'ONLINE') {
      return res.status(409).json({ error: 'Firewall already running' });
    }
    
    const iface = (req.body && req.body.iface) ? String(req.body.iface) : 'lo';

    if (await hasSystemd()) {
      const unit = serviceName(iface);
      if (SUDO_PASSWORD) {
        const systemctlCmd = spawn('sudo', ['-S', 'systemctl', 'start', unit], { cwd: rootDir });
        let stderr = '';
        systemctlCmd.stderr.on('data', (data) => { stderr += data.toString(); });
        systemctlCmd.stdin.write(SUDO_PASSWORD + '\n');
        systemctlCmd.stdin.end();
        systemctlCmd.on('close', (code) => {
          setTimeout(async () => {
            const status = await getFirewallStatus();
            if (code !== 0) return res.status(500).json({ status, error: 'systemd start failed: ' + stderr });
            return res.json({ status, message: 'Firewall started (systemd)' });
          }, 1200);
        });
        systemctlCmd.on('error', (err) => {
          res.status(500).json({ error: 'Failed to start systemctl: ' + err.message });
        });
      } else {
        exec(`sudo systemctl start ${unit}`, (error) => {
          setTimeout(async () => {
            const status = await getFirewallStatus();
            if (error) return res.status(500).json({ status, error: 'systemd start failed' });
            return res.json({ status, message: 'Firewall started (systemd)' });
          }, 1200);
        });
      }
    } else {
      execFirewall(['--run', iface]).catch(() => {});
      setTimeout(async () => {
        const status = await getFirewallStatus();
        res.json({ status, message: 'Firewall started (direct)' });
      }, 1200);
    }
    
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/firewall/stop', async (req, res) => {
  try {
    const iface = (req.body && req.body.iface) ? String(req.body.iface) : null;
    if (await hasSystemd()) {
      const unit = serviceName(iface || 'lo');
      if (SUDO_PASSWORD) {
        const systemctlCmd = spawn('sudo', ['-S', 'systemctl', 'stop', unit], { cwd: rootDir });
        systemctlCmd.stdin.write(SUDO_PASSWORD + '\n');
        systemctlCmd.stdin.end();
        systemctlCmd.on('close', () => {
          setTimeout(async () => {
            const status = await getFirewallStatus();
            res.json({ status, message: 'Firewall stopped (systemd)' });
          }, 600);
        });
        systemctlCmd.on('error', (err) => {
          res.status(500).json({ error: 'Failed to stop systemctl: ' + err.message });
        });
      } else {
        exec(`sudo systemctl stop ${unit}`, () => {
          setTimeout(async () => {
            const status = await getFirewallStatus();
            res.json({ status, message: 'Firewall stopped (systemd)' });
          }, 600);
        });
      }
    } else {
      if (SUDO_PASSWORD) {
        const pkillCmd = spawn('sudo', ['-S', 'pkill', '-f', 'firewall.*--run'], { cwd: rootDir });
        pkillCmd.stdin.write(SUDO_PASSWORD + '\n');
        pkillCmd.stdin.end();
        pkillCmd.on('close', () => {
          setTimeout(async () => {
            const status = await getFirewallStatus();
            res.json({ status, message: 'Firewall stopped (direct)' });
          }, 600);
        });
        pkillCmd.on('error', (err) => {
          res.status(500).json({ error: 'Failed to stop firewall: ' + err.message });
        });
      } else {
        exec('sudo pkill -f "firewall.*--run"', () => {
          setTimeout(async () => {
            const status = await getFirewallStatus();
            res.json({ status, message: 'Firewall stopped (direct)' });
          }, 600);
        });
      }
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/logs', (req, res) => {
  try {
    const logPath = path.join(rootDir, 'firewall.log');
    const logs = fs.readFileSync(logPath, 'utf8');
    const lines = logs.split('\n').filter(line => line.trim()).slice(-200);
    res.json({ logs: lines });
  } catch (e) {
    res.json({ logs: [], error: 'Log file not found or empty' });
  }
});

app.get('/api/user', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.json({ username: req.session.username || ADMIN_USERNAME });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

app.get('/api/settings', (req, res) => {
  try {
    const settings = readFirewallSettings();
    res.json(settings);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/settings', async (req, res) => {
  try {
    const status = await getFirewallStatus();
    if (status === 'ONLINE') {
      return res.status(409).json({ error: 'Cannot modify settings while firewall is running' });
    }
    
    const currentSettings = readFirewallSettings();
    const newSettings = {
      strict_mode: req.body.strict_mode !== undefined ? (req.body.strict_mode ? 1 : 0) : currentSettings.strict_mode,
      allow_dns: req.body.allow_dns !== undefined ? (req.body.allow_dns ? 1 : 0) : currentSettings.allow_dns,
      allow_icmp: req.body.allow_icmp !== undefined ? (req.body.allow_icmp ? 1 : 0) : currentSettings.allow_icmp,
      interface: req.body.interface || currentSettings.interface
    };
    
    writeFirewallSettings(newSettings);
    res.json({ success: true, settings: newSettings });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.use(express.static(rootDir));

app.use(requireAuth);

app.get('/', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.sendFile(path.join(rootDir, 'fd.html'));
  } else {
    res.redirect('/login.html');
  }
});

app.get('/logs.html', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.sendFile(path.join(rootDir, 'logs.html'));
  } else {
    res.redirect('/login.html');
  }
});

app.get('/settings.html', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.sendFile(path.join(rootDir, 'settings.html'));
  } else {
    res.redirect('/login.html');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
