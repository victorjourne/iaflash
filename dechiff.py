# -*- coding: utf-8 -*-
import os
import re, os, time, io, datetime
import hashlib
import gnupg
import json
import glob
import tarfile
import logging

from multiprocessing import Process, Queue

#### ce programme vise à decrypter et detarer les données du CNT
#### la clé privée et la passphrase doit être sockée dans les variables d'environnement gpg_private_key et gpg_passphrase


options = {
    "force": True,
    "remove_gpg" : False,
    "remove_tar" : True,
    "decrypt": True,
    "detar": True,
    "decrypt_detar": True,
    "threads": 2,
    "img_dir": "VIT3/img",
    "csv_dir": "VIT3/csv",
    "done_dir": "VIT3/done",
    "tar_dir": "VIT3/tar"
}



# répertoire cible
#source = dataiku.Folder("LWWz0gJD")
source = '/media/usbdisk1/VIT/'
#destination = dataiku.Folder("uO8kes2N")
destination = '/home/dss'

# setup chiffrement

filename = os.path.join('mykeys.json')
with open(filename) as json_data:
    mykeys = json.load(json_data)

gpg_private_key = mykeys['gpg_private_key'] # dataiku.get_custom_variables()["gpg_private_key"]
gpg_passphrase = mykeys['gpg_passphrase'] # dataiku.get_custom_variables()["gpg_passphrase"]

gpg = gnupg.GPG(verbose=True)
import_result = gpg.import_keys(gpg_private_key)

def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()


def decrypt_detar(i,file, process_queue, results):
    success = False
    with open(os.path.join(source, file), 'rb') as f:
        output_str = ""
        if 'MIF' in file:
            output = options['img_dir']
        else:
            output = options['csv_dir']

        if not os.path.isdir(os.path.join(destination, options['done_dir'])):
            print('Creating {} because it dont exist'.format(options['done_dir']))
            os.mkdir(os.path.join(destination, options['done_dir']))
        if not os.path.isdir(os.path.join(destination, options['tar_dir'])):
            print('Creating {} because it dont exist'.format(options['tar_dir']))
            os.mkdir(os.path.join(destination, options['tar_dir']))
        #try:
        #    os.mkdir(os.path.join(destination, options['done_dir']))
        #except:
        #    pass
        #try:
        #    os.mkdir(os.path.join(destination, options['tar_dir']))
        #except:
        #    pass
        done_file = os.path.join(destination, options['done_dir'], re.sub(r'.*/', '', file))
        failed_file = os.path.join(destination, options['done_dir'], re.sub(r'.*/', '', file + '.failed'))
        tar_file = os.path.join(destination, options['tar_dir'], re.sub(r'.*/', '', file.replace('.gpg', '')))

        if (not options['force']) & (os.path.isfile(done_file)):
            if (options['force']):
                print("forcing treatment of {} whereas previously marked as done".format(file))
                output_str = output_str + "forcing treatment of {} whereas previously marked as done\n".format(file)
            else:
                print("skipping {}".format(file))
                output_str = output_str + "skipping {} as previously marked as done\n".format(file)
        else:
            decrypt_success = False
            if options['decrypt']:
                print("decrypting {} to {}".format(file, tar_file))
                output_str = output_str + "decrypting {} to {}\n".format(file, tar_file)
                status = gpg.decrypt_file(f, passphrase = gpg_passphrase, output = tar_file)
                decrypt_success = status.ok
            if ((os.path.isfile(tar_file))&(decrypt_success | options['detar'])):
                print("detaring {}".format(tar_file))
                output_str = output_str + "detaring {}\n".format(tar_file)
                try:
                    with tarfile.open(tar_file) as tar:
                        for member in tar.getmembers():
                            print("extracting {}".format(member.name))
                            output_str = output_str + "extracting {}\n".format(member.name)
                            if member.isreg():  # skip if the TarInfo is not files
                                member.name = re.sub(r'/DATA/[^/]*/', '', member.name)
                                try:
                                    os.remove(os.path.join(destination, output))
                                    print("cleaning already existing file {}".format(output))
                                except:
                                    pass
                                tar.extract(member, os.path.join(destination, output))
                                print("extracted {}/{}".format(output, member.name))
                                output_str = output_str + "extracted {}/{}\n".format(output, member.name)
                    if (options['remove_tar']):
                        os.remove(tar_file)
                        print("removed {}".format(tar_file))
                        output_str = output_str + "removed {}\n".format(tar_file)
                except:
                    print("problem while detaring {}".format(tar_file))
                    output_str = output_str + "problem while detaring {}\n".format(tar_file)
                with open(done_file, 'w+') as f:
                    output_str = output_str + "{} done\n".format(datetime.datetime.now())
                    f.write(output_str)
                success = True
            else:
                if (not options['force']):
                    # logging.warning("decrypting {} failed:\n{}\n{}".format(file, decrypted_data.status, decrypted_data.stderr))
                    logging.warning("decrypting {} failed:\n{}\n{}".format(file, status.status, status.stderr))
                    with open(failed_file, 'w+') as f:
                        output_str = output_str + "decrypting {} failed:\n{}\n{}\n".format(file, status.status, status.stderr)
                        output_str = output_str + "{} failed\n".format(datetime.datetime.now())
                        f.write(output_str)
    process_queue.get(i)
    results.put(success)
    if success:
        print('thread {} successfully ended'.format(file))
    else:
        if (options['force'] & (not options['decrypt'])):
            print('thread {} had nothing to do'.format(file))
        else:
            print('thread {} failed'.format(file))


if options['decrypt_detar']:
    # decrypt
    # pattern de fichiers à scruter (mode regex) 
    pattern = '.+\/MIF.*\.(gpg)$'
    #print("essai {}".format(source.list_paths_in_partition()))
    print(source)
    print("essai {}".format(os.listdir(source)))
    files = list()
    for subdir in os.listdir(source):
        for root, directories, filenames in os.walk(os.path.join(source, subdir)):
            for filename in filenames:
                files.append( os.path.join(subdir,filename))
    #for root, directories, filenames in os.walk(source):
    #    for filename in filenames:
    #        files.append( filename)
    #        #files.append( os.path.join(root,filename))
    print(files)
    #print([i for i in glob.iglob(source + '*', recursive=True)])
    #dir = [ x.replace('/','', 1) for x in source.list_paths_in_partition() if re.match(glob,x)]
    #dir = [ x.replace('/','', 1) for x in files if re.match(pattern,x)]
    dir = [ x for x in files if re.match(pattern,x)]
    print(json.dumps(dir))
    process_queue = Queue(options['threads'])
    results = Queue()
    for i, file in enumerate(dir):
        process_queue.put(i)
        thread = Process(target=decrypt_detar, args=[i, file, process_queue, results])
        thread.start()
