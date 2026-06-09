import { useState, useEffect, useMemo } from 'react';

interface ForwardRule {
  proto: number;
  local_port: number;
  forward_ip: string;
  forward_port: number;
  forward_mac: number[];
}

interface ConnectedNodeInfo {
  node_id: string;
  group: string;
  hostname: string;
  rules: ForwardRule[];
}

export default function App() {
  const [nodes, setNodes] = useState<ConnectedNodeInfo[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'rules' | 'diff'>('rules');

  // Rule Form State
  const [formProto, setFormProto] = useState<'tcp' | 'udp'>('tcp');
  const [formLocalPort, setFormLocalPort] = useState<string>('');
  const [formForwardIp, setFormForwardIp] = useState<string>('');
  const [formForwardPort, setFormForwardPort] = useState<string>('');
  const [targetGroup, setTargetGroup] = useState<string>('default');
  const [customTargets, setCustomTargets] = useState<boolean>(false);
  const [selectedNodeTargets, setSelectedNodeTargets] = useState<string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  // Poll intervals
  useEffect(() => {
    fetchNodes();
    const timer = setInterval(fetchNodes, 3000);
    return () => clearInterval(timer);
  }, []);

  const fetchNodes = async () => {
    try {
      const res = await fetch('/api/nodes');
      if (!res.ok) throw new Error('Failed to fetch nodes');
      const data = await res.json();
      setNodes(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Error loading agent nodes info');
    }
  };

  // Groups list
  const groups = useMemo(() => {
    const set = new Set<string>();
    nodes.forEach(n => set.add(n.group));
    return Array.from(set);
  }, [nodes]);

  // Set default group when groups change
  useEffect(() => {
    if (groups.length > 0 && !groups.includes(targetGroup)) {
      setTargetGroup(groups[0]);
    }
  }, [groups]);

  // Node ID details selection
  const selectedNode = useMemo(() => {
    return nodes.find(n => n.node_id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  // Set initial selected node id
  useEffect(() => {
    if (nodes.length > 0 && !selectedNodeId) {
      setSelectedNodeId(nodes[0].node_id);
    }
  }, [nodes]);

  // Nodes filtered by current target group
  const nodesInTargetGroup = useMemo(() => {
    return nodes.filter(n => n.group === targetGroup);
  }, [nodes, targetGroup]);

  // Initialize selected node targets when group changes
  useEffect(() => {
    setSelectedNodeTargets(nodesInTargetGroup.map(n => n.node_id));
  }, [nodesInTargetGroup]);

  const handleTargetNodeCheckboxChange = (nodeId: string) => {
    setSelectedNodeTargets(prev =>
      prev.includes(nodeId) ? prev.filter(id => id !== nodeId) : [...prev, nodeId]
    );
  };

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    const localPort = parseInt(formLocalPort);
    const forwardPort = parseInt(formForwardPort);

    if (isNaN(localPort) || isNaN(forwardPort) || !formForwardIp) {
      setFormError('Please fill in all target rule fields with valid inputs.');
      return;
    }

    const payload = {
      group: targetGroup,
      node_ids: customTargets ? selectedNodeTargets : null,
      proto: formProto,
      local_port: localPort,
      forward_ip: formForwardIp,
      forward_port: forwardPort,
    };

    try {
      const res = await fetch('/api/rules/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errTxt = await res.text();
        throw new Error(errTxt || 'Failed to add rule');
      }

      setFormSuccess('Add rule command dispatched successfully!');
      // Clear form inputs
      setFormLocalPort('');
      setFormForwardIp('');
      setFormForwardPort('');
      fetchNodes();
    } catch (err: any) {
      setFormError(err.message || 'Error communicating with manager');
    }
  };

  const handleDeleteRule = async (proto: string, localPort: number, nodeIds: string[] | null) => {
    if (!confirm(`Are you sure you want to delete the NAT rule for ${proto.toUpperCase()} Port ${localPort}?`)) {
      return;
    }

    const payload = {
      group: targetGroup,
      node_ids: nodeIds,
      proto,
      local_port: localPort,
    };

    try {
      const res = await fetch('/api/rules/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errTxt = await res.text();
        throw new Error(errTxt || 'Failed to delete rule');
      }

      fetchNodes();
    } catch (err: any) {
      alert(`Error deleting rule: ${err.message}`);
    }
  };

  // Diff Auditor computation
  const diffAuditList = useMemo(() => {
    const groupNodes = nodes.filter(n => n.group === targetGroup);
    if (groupNodes.length === 0) return [];

    // Map rule signature -> Rule metadata and Node status mapping
    const rulesMap = new Map<string, {
      proto: string;
      local_port: number;
      forward_ip: string;
      forward_port: number;
      nodePresence: Record<string, boolean>; // node_id -> exists
    }>();

    groupNodes.forEach(node => {
      node.rules.forEach(rule => {
        const protoStr = rule.proto === 6 ? 'tcp' : 'udp';
        const key = `${protoStr}:${rule.local_port}:${rule.forward_ip}:${rule.forward_port}`;
        
        if (!rulesMap.has(key)) {
          rulesMap.set(key, {
            proto: protoStr,
            local_port: rule.local_port,
            forward_ip: rule.forward_ip,
            forward_port: rule.forward_port,
            nodePresence: {},
          });
        }
        
        rulesMap.get(key)!.nodePresence[node.node_id] = true;
      });
    });

    const list = Array.from(rulesMap.values());

    // Check discrepancy status for each rule signature
    return list.map(item => {
      const missingNodes = groupNodes.filter(n => !item.nodePresence[n.node_id]);
      const isConsistent = missingNodes.length === 0;

      return {
        ...item,
        isConsistent,
        missingNodeIds: missingNodes.map(n => n.node_id),
      };
    });
  }, [nodes, targetGroup]);

  return (
    <div style={{ display: 'flex', flex: 1, minHeight: '100vh', color: '#e2e8f0' }}>
      
      {/* Sidebar: Node Registry */}
      <div className="glass-panel" style={{ width: '280px', borderRight: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column', backgroundColor: 'rgba(15, 23, 42, 0.4)' }}>
        <div style={{ padding: '20px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ fontSize: '24px' }}>🔀</div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '16px', color: '#fff' }}>XDP NAT Manager</div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>Daemons Hub</div>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '15px' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#475569', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: '10px' }}>
            Connected Agents ({nodes.length})
          </div>

          {nodes.length === 0 ? (
            <div style={{ padding: '20px 0', textAlign: 'center', color: '#475569', fontSize: '13px' }}>
              No active nodes connected.<br/>Start daemons with<br/>
              <code>--manager-url ws://...</code>
            </div>
          ) : (
            // Grouping nodes
            groups.map(group => (
              <div key={group} style={{ marginBottom: '18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 6px', fontSize: '11px', color: '#a855f7', fontWeight: 600, backgroundColor: 'rgba(147,51,234,0.08)', borderRadius: '4px', marginBottom: '6px' }}>
                  <span>🏷️ Group: {group}</span>
                </div>
                {nodes.filter(n => n.group === group).map(node => (
                  <div
                    key={node.node_id}
                    onClick={() => setSelectedNodeId(node.node_id)}
                    style={{
                      padding: '10px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      backgroundColor: selectedNodeId === node.node_id ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                      border: selectedNodeId === node.node_id ? '1px solid rgba(6, 182, 212, 0.3)' : '1px solid transparent',
                      marginBottom: '4px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 500, color: selectedNodeId === node.node_id ? '#22d3ee' : '#fff', fontSize: '14px' }}>
                        {node.node_id}
                      </span>
                      <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981', display: 'inline-block', boxShadow: '0 0 8px #10b981' }}></span>
                    </div>
                    <div style={{ fontSize: '11px', color: '#64748b', marginTop: '3px' }}>
                      Host: {node.hostname}
                    </div>
                  </div>
                ))}
              </div>
            ))
          )}
        </div>

        <div style={{ padding: '15px', borderTop: '1px solid rgba(255,255,255,0.05)', backgroundColor: 'rgba(10, 15, 30, 0.5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: '#64748b' }}>
            <span style={{ position: 'relative', display: 'flex', height: '8px', width: '8px' }}>
              <span className="pulse-glow" style={{ position: 'absolute', display: 'inline-flex', height: '100%', width: '100%', borderRadius: '50%', backgroundColor: '#22d3ee', opacity: 0.75 }}></span>
              <span style={{ position: 'relative', display: 'inline-flex', borderRadius: '50%', height: '8px', width: '8px', backgroundColor: '#06b6d4' }}></span>
            </span>
            <span>Manager daemon status: Active</span>
          </div>
        </div>
      </div>

      {/* Main Workspace Panel */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', backgroundColor: '#0d0f14' }}>
        
        {/* Header toolbar */}
        <div className="glass-panel" style={{ padding: '15px 30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', borderRadius: 0 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: '20px', fontWeight: 600, letterSpacing: '-0.02em', background: 'linear-gradient(to right, #fff, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              NAT Rules Orchestrator Panel
            </h1>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>Manage driver-level NAT rules across multiple connected nodes</p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              onClick={() => setActiveTab('rules')}
              style={{
                padding: '8px 16px',
                borderRadius: '8px',
                border: activeTab === 'rules' ? '1px solid rgba(34,211,238,0.4)' : '1px solid rgba(255,255,255,0.05)',
                backgroundColor: activeTab === 'rules' ? 'rgba(34,211,238,0.1)' : 'rgba(255,255,255,0.02)',
                color: activeTab === 'rules' ? '#22d3ee' : '#94a3b8',
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              📋 Rules Dashboard
            </button>
            <button
              onClick={() => setActiveTab('diff')}
              style={{
                padding: '8px 16px',
                borderRadius: '8px',
                border: activeTab === 'diff' ? '1px solid rgba(168,85,247,0.4)' : '1px solid rgba(255,255,255,0.05)',
                backgroundColor: activeTab === 'diff' ? 'rgba(168,85,247,0.1)' : 'rgba(255,255,255,0.02)',
                color: activeTab === 'diff' ? '#c084fc' : '#94a3b8',
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              ⚖️ Cluster Diff Auditor
            </button>
          </div>
        </div>

        {error && (
          <div style={{ margin: '20px 30px', padding: '12px 20px', borderRadius: '8px', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: '#f87171', fontSize: '14px' }}>
            ⚠️ <strong>Error connecting:</strong> {error}
          </div>
        )}

        {/* Tab 1: Rules management dashboard */}
        {activeTab === 'rules' && (
          <div style={{ padding: '30px', display: 'flex', gap: '30px', flex: 1, overflowY: 'auto' }}>
            
            {/* Left section: Node rules list */}
            <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div className="glass-panel glow-border-cyan" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                  <h2 style={{ margin: 0, fontSize: '16px', color: '#fff' }}>
                    Active NAT Rules on <span style={{ color: '#22d3ee' }}>{selectedNodeId || 'NoneSelected'}</span>
                  </h2>
                  {selectedNode && (
                    <span style={{ fontSize: '12px', color: '#64748b' }}>
                      Group: {selectedNode.group} | Host: {selectedNode.hostname}
                    </span>
                  )}
                </div>

                {!selectedNode ? (
                  <div style={{ padding: '40px', textAlign: 'center', color: '#475569' }}>
                    Select a node from the sidebar to inspect rules list.
                  </div>
                ) : selectedNode.rules.length === 0 ? (
                  <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                    No dynamic NAT rule mappings registered on this node.
                  </div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                        <th style={{ padding: '12px 8px' }}>Proto</th>
                        <th style={{ padding: '12px 8px' }}>Local Port</th>
                        <th style={{ padding: '12px 8px' }}>Forward Target</th>
                        <th style={{ padding: '12px 8px' }}>Resolved MAC</th>
                        <th style={{ padding: '12px 8px', textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedNode.rules.map((rule, idx) => {
                        const protoStr = rule.proto === 6 ? 'tcp' : 'udp';
                        return (
                          <tr key={idx} className="slide-in" style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', fontSize: '14px', transition: 'background-color 0.2s' }}>
                            <td style={{ padding: '12px 8px' }}>
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 600,
                                textTransform: 'uppercase',
                                backgroundColor: protoStr === 'tcp' ? 'rgba(34,211,238,0.1)' : 'rgba(168,85,247,0.1)',
                                color: protoStr === 'tcp' ? '#22d3ee' : '#c084fc'
                              }}>
                                {protoStr}
                              </span>
                            </td>
                            <td style={{ padding: '12px 8px', fontWeight: 500 }}>{rule.local_port}</td>
                            <td style={{ padding: '12px 8px' }}>{rule.forward_ip}:{rule.forward_port}</td>
                            <td style={{ padding: '12px 8px', fontFamily: 'monospace', color: '#64748b' }}>
                              {rule.forward_mac.map(b => b.toString(16).padStart(2, '0')).join(':')}
                            </td>
                            <td style={{ padding: '12px 8px', textAlign: 'right' }}>
                              <button
                                onClick={() => handleDeleteRule(protoStr, rule.local_port, [selectedNode.node_id])}
                                style={{
                                  background: 'rgba(239, 68, 68, 0.1)',
                                  border: '1px solid rgba(239, 68, 68, 0.2)',
                                  color: '#ef4444',
                                  padding: '5px 10px',
                                  borderRadius: '6px',
                                  cursor: 'pointer',
                                  fontSize: '12px',
                                  transition: 'all 0.2s'
                                }}
                                onMouseEnter={(e) => {
                                  e.currentTarget.style.background = '#ef4444';
                                  e.currentTarget.style.color = '#fff';
                                }}
                                onMouseLeave={(e) => {
                                  e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)';
                                  e.currentTarget.style.color = '#ef4444';
                                }}
                              >
                                🗑️ Remove
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* Right section: Create Rule Form */}
            <div style={{ flex: 1 }}>
              <div className="glass-panel" style={{ padding: '20px', position: 'sticky', top: '30px' }}>
                <h2 style={{ margin: '0 0 15px 0', fontSize: '16px', color: '#fff' }}>Deploy Rules Command</h2>
                
                {formError && (
                  <div style={{ padding: '10px 15px', borderRadius: '6px', backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: '#f87171', fontSize: '13px', marginBottom: '15px' }}>
                    ⚠️ {formError}
                  </div>
                )}
                {formSuccess && (
                  <div style={{ padding: '10px 15px', borderRadius: '6px', backgroundColor: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', color: '#34d399', fontSize: '13px', marginBottom: '15px' }}>
                    ✅ {formSuccess}
                  </div>
                )}

                <form onSubmit={handleAddRule} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                  
                  {/* Target Group Selector */}
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: '#64748b', fontWeight: 500, marginBottom: '5px' }}>Target Group</label>
                    <select
                      value={targetGroup}
                      onChange={(e) => setTargetGroup(e.target.value)}
                      style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.05)', color: '#fff' }}
                    >
                      {groups.length === 0 ? (
                        <option value="default">default</option>
                      ) : (
                        groups.map(g => (
                          <option key={g} value={g}>{g}</option>
                        ))
                      )}
                    </select>
                  </div>

                  {/* Target Scope Mode */}
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: '#64748b', fontWeight: 500, marginBottom: '8px' }}>Target Mode</label>
                    <div style={{ display: 'flex', gap: '20px', fontSize: '14px' }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                        <input
                          type="radio"
                          checked={!customTargets}
                          onChange={() => setCustomTargets(false)}
                          style={{ accentColor: '#06b6d4' }}
                        />
                        Whole Group
                      </label>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                        <input
                          type="radio"
                          checked={customTargets}
                          onChange={() => setCustomTargets(true)}
                          style={{ accentColor: '#06b6d4' }}
                        />
                        Specific Nodes
                      </label>
                    </div>
                  </div>

                  {/* Specific Nodes Checklist */}
                  {customTargets && (
                    <div className="slide-in" style={{ padding: '10px 12px', borderRadius: '6px', backgroundColor: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.05)', maxHeight: '120px', overflowY: 'auto' }}>
                      <span style={{ fontSize: '11px', color: '#64748b', display: 'block', marginBottom: '5px' }}>Select Target Nodes</span>
                      {nodesInTargetGroup.length === 0 ? (
                        <span style={{ fontSize: '12px', color: '#475569' }}>No nodes in this group</span>
                      ) : (
                        nodesInTargetGroup.map(n => (
                          <label key={n.node_id} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', padding: '3px 0', cursor: 'pointer' }}>
                            <input
                              type="checkbox"
                              checked={selectedNodeTargets.includes(n.node_id)}
                              onChange={() => handleTargetNodeCheckboxChange(n.node_id)}
                              style={{ accentColor: '#06b6d4' }}
                            />
                            {n.node_id}
                          </label>
                        ))
                      )}
                    </div>
                  )}

                  {/* Rule details */}
                  <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '15px' }}>
                    <div style={{ display: 'flex', gap: '10px', marginBottom: '12px' }}>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '5px' }}>Protocol</label>
                        <select
                          value={formProto}
                          onChange={(e) => setFormProto(e.target.value as 'tcp' | 'udp')}
                          style={{ width: '100%', padding: '8px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.05)', color: '#fff' }}
                        >
                          <option value="tcp">TCP</option>
                          <option value="udp">UDP</option>
                        </select>
                      </div>
                      <div style={{ flex: 2 }}>
                        <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '5px' }}>Local Port</label>
                        <input
                          type="number"
                          placeholder="e.g. 80"
                          value={formLocalPort}
                          onChange={(e) => setFormLocalPort(e.target.value)}
                          style={{ width: '85%', padding: '8px 10px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.05)', color: '#fff' }}
                        />
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '10px' }}>
                      <div style={{ flex: 2 }}>
                        <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '5px' }}>Forward Target IP</label>
                        <input
                          type="text"
                          placeholder="e.g. 192.168.1.100"
                          value={formForwardIp}
                          onChange={(e) => setFormForwardIp(e.target.value)}
                          style={{ width: '90%', padding: '8px 10px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.05)', color: '#fff' }}
                        />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '5px' }}>Port</label>
                        <input
                          type="number"
                          placeholder="8080"
                          value={formForwardPort}
                          onChange={(e) => setFormForwardPort(e.target.value)}
                          style={{ width: '80%', padding: '8px 10px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.05)', color: '#fff' }}
                        />
                      </div>
                    </div>
                  </div>

                  <button
                    type="submit"
                    style={{
                      marginTop: '10px',
                      padding: '10px',
                      borderRadius: '8px',
                      border: 'none',
                      background: 'linear-gradient(to right, #06b6d4, #3b82f6)',
                      color: '#fff',
                      fontWeight: 600,
                      cursor: 'pointer',
                      boxShadow: '0 4px 12px rgba(6, 182, 212, 0.3)',
                      transition: 'transform 0.1s'
                    }}
                    onMouseDown={(e) => e.currentTarget.style.transform = 'scale(0.98)'}
                    onMouseUp={(e) => e.currentTarget.style.transform = 'scale(1)'}
                  >
                    🚀 Push NAT Rule Mapping
                  </button>
                </form>
              </div>
            </div>

          </div>
        )}

        {/* Tab 2: Config comparison auditor */}
        {activeTab === 'diff' && (
          <div style={{ padding: '30px', flex: 1, overflowY: 'auto' }}>
            <div className="glass-panel glow-border-purple" style={{ padding: '20px' }}>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '16px', color: '#fff' }}>Cluster Configuration Audit Matrix</h2>
                  <p style={{ margin: '5px 0 0 0', fontSize: '12px', color: '#64748b' }}>
                    Auditing rules for group: <strong style={{ color: '#c084fc' }}>{targetGroup}</strong>
                  </p>
                </div>

                <div>
                  <label style={{ fontSize: '13px', color: '#64748b', marginRight: '8px' }}>Select Audit Group:</label>
                  <select
                    value={targetGroup}
                    onChange={(e) => setTargetGroup(e.target.value)}
                    style={{ padding: '6px 12px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.05)', color: '#fff' }}
                  >
                    {groups.map(g => (
                      <option key={g} value={g}>{g}</option>
                    ))}
                  </select>
                </div>
              </div>

              {nodesInTargetGroup.length === 0 ? (
                <div style={{ padding: '40px', textAlign: 'center', color: '#475569' }}>
                  No active connected nodes found in this group.
                </div>
              ) : diffAuditList.length === 0 ? (
                <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                  No rules configured on any nodes in this group.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                      <th style={{ padding: '12px 8px' }}>NAT Rule Config Mapping</th>
                      {nodesInTargetGroup.map(node => (
                        <th key={node.node_id} style={{ padding: '12px 8px', textAlign: 'center' }}>
                          {node.node_id}
                        </th>
                      ))}
                      <th style={{ padding: '12px 8px', textAlign: 'center' }}>Status</th>
                      <th style={{ padding: '12px 8px', textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diffAuditList.map((item, idx) => (
                      <tr key={idx} style={{
                        borderBottom: '1px solid rgba(255,255,255,0.02)',
                        fontSize: '14px',
                        backgroundColor: !item.isConsistent ? 'rgba(239, 68, 68, 0.03)' : 'transparent'
                      }}>
                        {/* Rule definition */}
                        <td style={{ padding: '16px 8px' }}>
                          <span style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: 600,
                            textTransform: 'uppercase',
                            marginRight: '8px',
                            backgroundColor: item.proto === 'tcp' ? 'rgba(34,211,238,0.1)' : 'rgba(168,85,247,0.1)',
                            color: item.proto === 'tcp' ? '#22d3ee' : '#c084fc'
                          }}>
                            {item.proto}
                          </span>
                          <strong>{item.local_port}</strong>
                          <span style={{ color: '#64748b', margin: '0 8px' }}>→</span>
                          <span>{item.forward_ip}:{item.forward_port}</span>
                        </td>

                        {/* Node columns */}
                        {nodesInTargetGroup.map(node => {
                          const exists = item.nodePresence[node.node_id];
                          return (
                            <td key={node.node_id} style={{ padding: '12px 8px', textAlign: 'center' }}>
                              {exists ? (
                                <span style={{ color: '#10b981', fontSize: '16px', fontWeight: 'bold' }}>✓</span>
                              ) : (
                                <span style={{ color: '#ef4444', fontSize: '16px', fontWeight: 'bold' }}>✗</span>
                              )}
                            </td>
                          );
                        })}

                        {/* Status badge */}
                        <td style={{ padding: '12px 8px', textAlign: 'center' }}>
                          {item.isConsistent ? (
                            <span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '11px', backgroundColor: 'rgba(16,185,129,0.1)', color: '#10b981', border: '1px solid rgba(16,185,129,0.2)' }}>
                              Synced
                            </span>
                          ) : (
                            <span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '11px', backgroundColor: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.2)' }}>
                              Mismatch
                            </span>
                          )}
                        </td>

                        {/* Audit syncing actions */}
                        <td style={{ padding: '12px 8px', textAlign: 'right' }}>
                          {item.isConsistent ? (
                            <button
                              onClick={() => handleDeleteRule(item.proto, item.local_port, null)}
                              style={{
                                background: 'transparent',
                                border: '1px solid rgba(239, 68, 68, 0.3)',
                                color: '#f87171',
                                padding: '4px 10px',
                                borderRadius: '6px',
                                cursor: 'pointer',
                                fontSize: '12px'
                              }}
                            >
                              🗑️ Group Del
                            </button>
                          ) : (
                            <button
                              onClick={async () => {
                                // Sync: Add rule to nodes that don't have it
                                const payload = {
                                  group: targetGroup,
                                  node_ids: item.missingNodeIds,
                                  proto: item.proto,
                                  local_port: item.local_port,
                                  forward_ip: item.forward_ip,
                                  forward_port: item.forward_port
                                };
                                try {
                                  const res = await fetch('/api/rules/add', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify(payload)
                                  });
                                  if (!res.ok) throw new Error(await res.text());
                                  fetchNodes();
                                } catch (e: any) {
                                  alert(`Sync error: ${e.message}`);
                                }
                              }}
                              style={{
                                background: 'rgba(168,85,247,0.1)',
                                border: '1px solid rgba(168,85,247,0.3)',
                                color: '#c084fc',
                                padding: '4px 10px',
                                borderRadius: '6px',
                                cursor: 'pointer',
                                fontSize: '12px',
                                fontWeight: 500
                              }}
                            >
                              🔄 Sync Cluster
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

            </div>
          </div>
        )}

      </div>

    </div>
  );
}
