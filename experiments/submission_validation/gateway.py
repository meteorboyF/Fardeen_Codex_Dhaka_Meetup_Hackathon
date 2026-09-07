#!/usr/bin/env python3
"""Launch the experiment gateway using local configuration without printing secrets."""
import os,sys,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[2]
env=os.environ.copy()
for line in (root/'.env').read_text().splitlines():
 if line.strip() and not line.lstrip().startswith('#') and '=' in line:
  k,v=line.split('=',1);env[k.strip()]=v.strip().strip('\"\'')
env['DB_PORT']='5433'
env['DOCUMENT_MATERIAL_DB_FALLBACK']='false'
env['JAVA_HOME']='/usr/lib/jvm/java-21-openjdk-amd64'
env['SPRING_PROFILES_ACTIVE']='audit-log-only' if '--database' in sys.argv else ''
env['AUDIT_ANCHOR_BACKFILL']='false' if '--no-anchor' in sys.argv else 'true'
env['AUDIT_ANCHOR_BATCH_SIZE']='200'
# Disable unrelated externally connected features during controlled local measurements.
env['OPENAI_API_KEY']='local-validation-unused'
args=[env['JAVA_HOME']+'/bin/java','-Xms256m','-Xmx768m','-jar','target/pangochain-backend-2.0.0.jar',
 '--spring.datasource.url=jdbc:postgresql://localhost:5433/pangochain?stringtype=unspecified',
 '--documents.material-db-fallback-enabled=false',
 '--logging.level.com.pangochain.backend=WARN']
os.chdir(root/'pangochain-backend')
os.execvpe(args[0],args,env)
