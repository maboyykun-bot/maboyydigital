"""Authenticated full-filesystem backup and validated restore. No exclusions."""
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES

MAGIC=b'MABOYY-BACKUP-1\0'
CHUNK=1024*1024


def digest(path):
    result=hashlib.sha256()
    with open(path,'rb') as handle:
        for data in iter(lambda:handle.read(CHUNK),b''):result.update(data)
    return result.hexdigest()


def inventory(root):
    root=Path(root).resolve()
    result=[]
    def visit(path):
        info=path.lstat()
        item={'path':path.relative_to(root).as_posix() or '.', 'mode':stat.S_IMODE(info.st_mode),
              'uid':info.st_uid,'gid':info.st_gid,'mtime_ns':info.st_mtime_ns,'atime_ns':info.st_atime_ns}
        if stat.S_ISLNK(info.st_mode):
            item.update(type='symlink',target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):item['type']='directory'
        elif stat.S_ISREG(info.st_mode):
            item.update(type='file',size=info.st_size,sha256=digest(path))
        else:raise RuntimeError('Unsupported special file; backup stopped: '+str(path))
        result.append(item)
        if item['type']=='directory':
            for child in sorted(path.iterdir(),key=lambda child:child.name):visit(child)
    visit(root)
    return result


def stable_view(items):
    return [{key:value for key,value in item.items() if key!='atime_ns'} for item in items]


def load_key(path,create=False):
    path=Path(path).resolve()
    if not path.exists() and create:
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'wb') as handle:handle.write(os.urandom(32))
    key=path.read_bytes()
    if len(key)!=32:raise ValueError('Backup key must contain exactly 32 random bytes.')
    if stat.S_IMODE(path.stat().st_mode)&0o077:raise ValueError('Backup key must have permission 600.')
    return key


def sqlite_snapshot(source,destination):
    source=Path(source).resolve()
    if not source.is_file():raise FileNotFoundError(source)
    destination=Path(destination)
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    source_conn=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=30)
    target_conn=sqlite3.connect(destination)
    try:
        source_conn.backup(target_conn,pages=256,sleep=.01)
        result=target_conn.execute('PRAGMA integrity_check').fetchall()
        if result!=[('ok',)]:raise RuntimeError('SQLite snapshot integrity failed.')
    finally:
        target_conn.close()
        source_conn.close()
    os.chmod(destination,0o600)
    return digest(destination)


def sqlite_contents(path):
    """Describe the consistent snapshot without recording any application rows."""
    path=Path(path).resolve()
    conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=30)
    try:
        schema=conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        schema_bytes=json.dumps(schema,ensure_ascii=False,separators=(',',':')).encode()
        counts={}
        for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            quoted='"'+name.replace('"','""')+'"'
            counts[name]=conn.execute('SELECT COUNT(*) FROM '+quoted).fetchone()[0]
        return {'schema_sha256':hashlib.sha256(schema_bytes).hexdigest(),
                'table_row_counts':counts}
    finally:conn.close()


def encrypt(source,destination,key,manifest_hash):
    nonce=os.urandom(12)
    header=MAGIC+nonce+bytes.fromhex(manifest_hash)
    cipher=AES.new(key,AES.MODE_GCM,nonce=nonce)
    cipher.update(header)
    with open(source,'rb') as incoming,open(destination,'xb') as outgoing:
        os.chmod(destination,0o600)
        outgoing.write(header)
        for data in iter(lambda:incoming.read(CHUNK),b''):outgoing.write(cipher.encrypt(data))
        outgoing.write(cipher.digest())
        outgoing.flush()
        os.fsync(outgoing.fileno())


def decrypt(archive,destination,key,manifest_hash):
    header_size=len(MAGIC)+12+32
    size=Path(archive).stat().st_size
    if size<header_size+16:raise ValueError('Encrypted archive is truncated.')
    with open(archive,'rb') as incoming,open(destination,'xb') as outgoing:
        header=incoming.read(header_size)
        if not header.startswith(MAGIC) or header[-32:]!=bytes.fromhex(manifest_hash):
            raise ValueError('Archive format or authenticated manifest does not match.')
        cipher=AES.new(key,AES.MODE_GCM,nonce=header[len(MAGIC):len(MAGIC)+12])
        cipher.update(header)
        remaining=size-header_size-16
        while remaining:
            data=incoming.read(min(CHUNK,remaining))
            if not data:raise ValueError('Encrypted archive is truncated.')
            outgoing.write(cipher.decrypt(data))
            remaining-=len(data)
        cipher.verify(incoming.read(16))


def restore_archive(tar_path,manifest,target):
    target=Path(target).resolve()
    if target.exists() and any(target.iterdir()):raise ValueError('Restore target must be empty.')
    target.mkdir(parents=True,exist_ok=True,mode=0o700)
    expected={'workspace' if item['path']=='.' else 'workspace/'+item['path']:item for item in manifest['entries']}
    expected.update({item['archive_path']:item for item in manifest['databases']})
    for storage in manifest.get('external_storages',[]):
        expected.update({storage['archive_prefix'] if item['path']=='.' else storage['archive_prefix']+'/'+item['path']:item
                         for item in storage['entries']})
    directory_metadata=[]
    with tarfile.open(tar_path,'r:gz') as archive:
        members=archive.getmembers()
        if len(members)!=len(expected) or {member.name for member in members}!=set(expected):
            raise ValueError('Archive file manifest differs from source manifest.')
        for member in members:
            item=expected[member.name]
            if 'uid' in item and (member.uid!=item['uid'] or member.gid!=item['gid']):
                raise ValueError('Ownership metadata mismatch.')
            if member.name.startswith('/') or '..' in Path(member.name).parts:raise ValueError('Unsafe archive path.')
            destination=target/member.name
            if not destination.resolve().is_relative_to(target):raise ValueError('Unsafe archive target.')
            destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if item.get('type')=='symlink':
                if not member.issym() or member.linkname!=item['target']:raise ValueError('Symlink metadata mismatch.')
                destination.symlink_to(item['target'])
                os.utime(destination,ns=(item['atime_ns'],item['mtime_ns']),follow_symlinks=False)
            elif item.get('type')=='directory':
                if not member.isdir() or member.mode!=item['mode']:raise ValueError('Directory metadata mismatch.')
                destination.mkdir(exist_ok=True,mode=0o700)
                directory_metadata.append((destination,item))
            else:
                if not (member.isfile() or member.islnk()):raise ValueError('File type mismatch.')
                handle=archive.extractfile(member)
                if handle is None:raise ValueError('Archive file cannot be read.')
                with handle,open(destination,'xb') as output:shutil.copyfileobj(handle,output,CHUNK)
                if digest(destination)!=item['sha256']:raise ValueError('Restored file checksum mismatch: '+member.name)
                if member.mode!=item['mode']:raise ValueError('File permission metadata mismatch.')
                if 'uid' in item and (member.uid!=item['uid'] or member.gid!=item['gid']):raise ValueError('Ownership metadata mismatch.')
                os.chmod(destination,item['mode'])
                os.utime(destination,ns=(item['atime_ns'],item['mtime_ns']))
        for destination,item in reversed(directory_metadata):
            os.chmod(destination,item['mode'])
            os.utime(destination,ns=(item['atime_ns'],item['mtime_ns']))
    for item in manifest['entries']:
        destination=target/'workspace'/item['path']
        info=destination.lstat()
        if stat.S_IMODE(info.st_mode)!=item['mode'] or info.st_mtime_ns!=item['mtime_ns']:
            raise ValueError('Restored metadata mismatch: '+item['path'])
    for storage in manifest.get('external_storages',[]):
        for item in storage['entries']:
            destination=target/storage['archive_prefix']/item['path']
            info=destination.lstat()
            if stat.S_IMODE(info.st_mode)!=item['mode'] or info.st_mtime_ns!=item['mtime_ns']:
                raise ValueError('Restored external metadata mismatch: '+item['path'])
    for item in manifest['databases']:
        conn=sqlite3.connect((target/item['archive_path']).as_uri()+'?mode=ro',uri=True)
        try:
            if conn.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('Restored SQLite snapshot is corrupt.')
        finally:conn.close()
        if 'contents' in item and sqlite_contents(target/item['archive_path'])!=item['contents']:
            raise ValueError('Restored SQLite schema or table counts differ from snapshot.')
    return {'entries_verified':len(expected)-len(manifest['databases']),'databases_verified':len(manifest['databases'])}


def clear_private_tree(path):
    # Restore validation contains read-only source directories; make only this
    # disposable restore tree writable before deleting it.
    for base,dirs,_ in os.walk(path,followlinks=False):
        os.chmod(base,0o700)
        for name in dirs:
            child=Path(base)/name
            if not child.is_symlink():os.chmod(child,0o700)
    shutil.rmtree(path)


def verify(folder,key_path,target=None):
    folder=Path(folder).resolve()
    manifest_bytes=(folder/'manifest.json').read_bytes()
    manifest=json.loads(manifest_bytes)
    if Path(manifest['archive']).name!=manifest['archive']:
        raise ValueError('Unsafe archive filename in manifest.')
    expected_checksums={line.split('  ',1)[1]:line.split('  ',1)[0] for line in (folder/'checksums.sha256').read_text().splitlines()}
    if set(expected_checksums)!={'manifest.json',manifest['archive']}:
        raise ValueError('Checksum inventory must include exactly the manifest and encrypted archive.')
    for name,expected in expected_checksums.items():
        if Path(name).name!=name or digest(folder/name)!=expected:raise ValueError('Backup checksum mismatch.')
    key=load_key(key_path)
    stage=Path(tempfile.mkdtemp(prefix='maboyy-backup-verify-',dir='/tmp'))
    try:
        tar_path=stage/'archive.tar.gz'
        decrypt(folder/manifest['archive'],tar_path,key,hashlib.sha256(manifest_bytes).hexdigest())
        result=restore_archive(tar_path,manifest,Path(target) if target else stage/'restore')
        result.update(authenticated_encryption='AES-256-GCM PASS',checksum='PASS',restore='PASS')
        return result
    finally:clear_private_tree(stage)


def discover_databases(roots,explicit):
    databases={str(Path(path).resolve()) for path in explicit}
    configured=os.getenv('DB_PATH','').strip()
    if configured:
        if not Path(configured).is_file():raise FileNotFoundError('Configured DB_PATH is inaccessible; backup stopped.')
        databases.add(str(Path(configured).resolve()))
    for root in roots:
        for item in inventory(root):
            if item['type']!='file':continue
            path=Path(root)/item['path']
            with open(path,'rb') as handle:header=handle.read(16)
            if header==b'SQLite format 3\0':databases.add(str(path.resolve()))
    for database in databases:
        with open(database,'rb') as handle:
            if handle.read(16)!=b'SQLite format 3\0':raise ValueError('Only consistent SQLite snapshots are supported by this project.')
    return sorted(databases)


def create(root,folder,key_path,label,databases=(),external=()):
    root=Path(root).resolve()
    folder=Path(folder).resolve()
    key_path=Path(key_path).resolve()
    if folder.is_relative_to(root) or key_path.is_relative_to(root) or key_path.is_relative_to(folder):
        raise ValueError('Archive and key must be outside the project; key must be outside the backup folder.')
    if folder.exists() and any(folder.iterdir()):raise ValueError('Backup folder must be new or empty.')
    key=load_key(key_path,create=True)
    folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    entries=inventory(root)
    external_storages=[]
    for index,path in enumerate(external):
        path=Path(path).resolve()
        if not path.is_dir():raise ValueError('External storage must be an accessible directory.')
        if path.is_relative_to(root):continue
        if folder.is_relative_to(path) or key_path.is_relative_to(path):
            raise ValueError('External storage must not contain archive or decryption key.')
        external_storages.append({'source':str(path),'archive_prefix':f'external-data/storage-{index}', 'entries':inventory(path)})
    databases=discover_databases([root]+[storage['source'] for storage in external_storages],databases)
    stage=Path(tempfile.mkdtemp(prefix='maboyy-backup-create-',dir='/tmp'))
    try:
        snapshots=[]
        for index,database in enumerate(databases):
            source=Path(database).resolve()
            destination=stage/f'database-{index}.sqlite'
            checksum=sqlite_snapshot(source,destination)
            info=destination.stat()
            snapshots.append({'source':str(source),'archive_path':f'database-{label}/database-{index}.sqlite',
                              'type':'file','mode':0o600,'mtime_ns':info.st_mtime_ns,'atime_ns':info.st_atime_ns,
                              'size':info.st_size,'sha256':checksum,'staging_path':str(destination),
                              'contents':sqlite_contents(destination)})
        # Reading an idle WAL database can create and retire SQLite sidecars,
        # changing its directory's mtime. Record the filesystem after all
        # consistent snapshots are closed. Every file is still inventoried;
        # later changes during archiving still fail the stable-view check.
        entries=inventory(root)
        for storage in external_storages:
            storage['entries']=inventory(storage['source'])
        manifest={'format':1,'created_at':datetime.now(timezone.utc).isoformat(),'source_root':str(root),
                  'archive':f'project-{label}-full.tar.gz.enc','entries':entries,
                  'databases':[{key:value for key,value in item.items() if key!='staging_path'} for item in snapshots],
                  'external_storages':external_storages,
                  'external_symlink_references':[item for item in entries if item['type']=='symlink'],
                  'limits':['Only accessible project files and explicitly identified external storage are included. Inventory external application volumes before claiming a production full backup.',
                            'External symlink targets are references unless passed through --external; symlinks are never followed automatically.',
                            'UID/GID are preserved in archive metadata; applying ownership on restore requires suitable OS privileges.']}
        tar_path=stage/'project.tar.gz'
        with tarfile.open(tar_path,'w:gz',format=tarfile.PAX_FORMAT,dereference=False) as archive:
            for item in entries:
                path=root/item['path']
                name='workspace' if item['path']=='.' else 'workspace/'+item['path']
                info=archive.gettarinfo(str(path),arcname=name)
                info.pax_headers['mtime']=str(item['mtime_ns']/1_000_000_000)
                info.pax_headers['atime']=str(item['atime_ns']/1_000_000_000)
                if item['type']=='file':
                    with open(path,'rb') as handle:archive.addfile(info,handle)
                else:archive.addfile(info)
            for item in snapshots:archive.add(item['staging_path'],arcname=item['archive_path'],recursive=False)
            for storage in external_storages:
                for item in storage['entries']:
                    path=Path(storage['source'])/item['path']
                    name=storage['archive_prefix'] if item['path']=='.' else storage['archive_prefix']+'/'+item['path']
                    info=archive.gettarinfo(str(path),arcname=name)
                    info.pax_headers['mtime']=str(item['mtime_ns']/1_000_000_000)
                    info.pax_headers['atime']=str(item['atime_ns']/1_000_000_000)
                    if item['type']=='file':
                        with open(path,'rb') as handle:archive.addfile(info,handle)
                    else:archive.addfile(info)
        if stable_view(entries)!=stable_view(inventory(root)):raise RuntimeError('Source changed while backing up; no verified backup created. Quiesce file writers and retry.')
        for storage in external_storages:
            if stable_view(storage['entries'])!=stable_view(inventory(storage['source'])):
                raise RuntimeError('External storage changed during backup; quiesce writers and retry.')
        manifest_bytes=json.dumps(manifest,ensure_ascii=False,indent=2).encode()
        manifest_path=folder/'manifest.json'
        manifest_path.write_bytes(manifest_bytes)
        os.chmod(manifest_path,0o600)
        archive_path=folder/manifest['archive']
        encrypt(tar_path,archive_path,key,hashlib.sha256(manifest_bytes).hexdigest())
        checksums=''.join(digest(path)+'  '+path.name+'\n' for path in (manifest_path,archive_path))
        (folder/'checksums.sha256').write_text(checksums)
        os.chmod(folder/'checksums.sha256',0o600)
        result=verify(folder,key_path)
        counts={kind:sum(item['type']==kind for item in entries) for kind in ('file','directory','symlink')}
        report=(f'# Full backup {label}\n\nSource: `{root}`\n\nArchive: `{archive_path}`\n\n'
                f'Files: {counts["file"]}; directories: {counts["directory"]}; symlinks: {counts["symlink"]}.\n\n'
                f'Checksums, authenticated encryption, archive manifest and temporary restore: PASS.\n\n'
                f'Consistent SQLite snapshots: {len(snapshots)}. Explicit external storage: {len(external_storages)}.\n\n'
                'The decryption key is stored separately, outside the project and backup folder. Do not publish it or place it in the source repository.\n\n'
                'All selected filesystem files, hidden files, dependencies, caches and old backups are included without exclusions. '
                'Symlinks remain symlinks; external targets are recorded as references. '
                'No claim is made for external data or secrets that were not accessible/identified. '
                'File writers must be quiesced for the complete filesystem inventory to remain stable.\n')
        (folder/'backup-report.md').write_text(report)
        os.chmod(folder/'backup-report.md',0o600)
        return {**result,**counts,'backup_folder':str(folder),'archive':str(archive_path),'database_snapshots':len(snapshots)}
    finally:clear_private_tree(stage)


def restore_database(folder,key_path,index,target):
    target=Path(target).resolve()
    if target.exists():raise ValueError('Database restore target must not exist; production databases are never overwritten automatically.')
    stage=Path(tempfile.mkdtemp(prefix='maboyy-db-restore-',dir='/tmp'))
    try:
        verify(folder,key_path,stage/'restore')
        manifest=json.loads((Path(folder)/'manifest.json').read_text())
        snapshot=manifest['databases'][index]
        source=stage/'restore'/snapshot['archive_path']
        target.parent.mkdir(parents=True,exist_ok=True)
        sqlite_snapshot(source,target)
        return {'restored_database':str(target),'checksum':digest(target),'integrity':'PASS',
                'notice':'Restored to a new path. Reconcile newer transactions before any production switch.'}
    finally:clear_private_tree(stage)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['create','verify','restore','restore-database'])
    parser.add_argument('--project')
    parser.add_argument('--folder',required=True)
    parser.add_argument('--key-file',required=True)
    parser.add_argument('--label',choices=['before','after','operational'],default='operational')
    parser.add_argument('--database',action='append',default=[])
    parser.add_argument('--external',action='append',default=[])
    parser.add_argument('--database-index',type=int,default=0)
    parser.add_argument('--target')
    args=parser.parse_args()
    if args.operation=='create':
        if not args.project:parser.error('--project is required for create')
        result=create(args.project,args.folder,args.key_file,args.label,args.database,args.external)
    elif args.operation=='restore-database':
        if not args.target:parser.error('--target is required and must not exist')
        result=restore_database(args.folder,args.key_file,args.database_index,args.target)
    else:
        if args.operation=='restore' and not args.target:parser.error('--target is required for restore; target must be empty')
        result=verify(args.folder,args.key_file,args.target if args.operation=='restore' else None)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
