import argparse
import os
import random
import shutil
import time
import warnings
import sys
import json
import pandas as pd

from environment import ROOT_DIR, TMP_DIR, DSS_DIR, API_KEY_VIT,PROJECT_KEY_VIT, DSS_HOST, VERTICA_HOST
from dss.api import read_dataframe


dataset_name = 'bbox_marque_modele_class'
columns = ['path','img_name','x1','y1','x2','y2','score','_rank','modele','marque']
limit = 1e8
sampling = 0.1
radar_type = {
        'ETE' : 'equipement terrain embarqu',
        'ETF' : 'equipement terrain fixe',
        'ETC' : 'equipement terrain chantier',
        'ETVM' : 'equipement terrain vitesse moyenne',
        'ETM' : 'equipement terrain mobile',
        'ETVLPL' : 'equipement terrain discriminant pl vl'
        }

parser = argparse.ArgumentParser(description='Filter Dataset From DSS and Write it')

parser.add_argument('--dir', metavar='DIR',
                    help='path to csv dataset')

parser.add_argument('--keep',dest='keep',action='store_true',
                    help='Drop and Create')

parser.add_argument( '--table', metavar='TABLE',type=str, default=dataset_name,
                    help='Number of lines to keep')

parser.add_argument('--status', metavar='STATUS DOSSIER',type=int, nargs='+',
                    choices=range(60),
                    help='Filter DI_StatutDossier')

parser.add_argument( '--modele', metavar='MODELE',type=str, nargs='+',
                    help='Filter Modele')

parser.add_argument('--sens', metavar='SENS DETECTION',type=str, nargs='+',
                    choices=['ELOI','RAPP','BI-DIRECTIONNEL'],
                    help='Filter Modele')

parser.add_argument('--radar', metavar='RADAR TYPE',type=str, nargs='+',
                    choices=radar_type.keys(),
                    help='Filter Modele')

parser.add_argument('--columns', metavar='COLUMNS',type=str, nargs='+',
                    help='Columns to retrieve',default=columns)

parser.add_argument('--sampling', metavar='SAMPLE',type=float,default=sampling,
                    help='Sampling rate when extracting')

parser.add_argument('-l', '--limit', metavar='LIMIT',type=int, default=limit,
                    help='Number of lines to keep')


init_dict = dict(table=dataset_name,sampling=sampling,limit=limit,columns=columns)

print('Read args')
def main():
    args = parser.parse_args()

    if (not args.keep) or (not os.path.exists(args.dir)):
        #print('=> drop and recreate')
        shutil.rmtree(args.dir, ignore_errors=True)

        os.makedirs(args.dir, exist_ok=True)

        df = read_df(args)
        print('Retrieve %s rows'%df.shape[0])
        df = create_mapping(args,df)
        write_df(args,df)

    return(args.dir)

def filter(**filt_dict):
    # init Namespace object from parser init states
    """
    args = parser.parse_args()
    print (parser)
    # overload args
    for key, val in filt_dict.items():
        setattr(args, key, val)

    """
    class Args:
        def __getattr__(self, name):
            return None

    args = Args()

    for key, val in init_dict.items():
        setattr(args, key, val)
    for key, val in filt_dict.items():
        setattr(args, key, val)
    
    return read_df(args)

def read_df(args):
    conditions = ''

    if args.modele :
        conditions += 'modele IN (%s) ' %', '.join(["'%s'"%col for col in  args.modele])

    if args.sens :
        conditions += ' AND '
        conditions += '"csa.Params_Leg.Sens_Detect" IN (%s) ' %', '.join(["'%s'"%col for col in  args.sens])

    if args.radar :
        conditions += ' AND '
        conditions += 'TYPEEQUIP_Libelle IN (%s) ' %', '.join(["'%s'"%radar_type[col] for col in  args.radar])

    #conditions ='join_marque_modele IS NOT NULL AND (DI_StatutDossier=4 OR DI_StatutDossier=6 OR DI_StatutDossier=13) '
    #DSS_HOST = VERTICA_HOST+":1000    print('There is %s images'%df.shape[0])
    df = read_dataframe(API_KEY_VIT,VERTICA_HOST,PROJECT_KEY_VIT,
        args.table,args.columns,conditions,args.limit,args.sampling)

    df = df[df.notnull()]
    return df

def create_mapping(args,df):
    df_class = df.groupby('_rank',sort=True)

    i = 0
    idx_to_class = {}

    for _rank, tmp in df_class:
        assert tmp['modele'].unique().shape[0] == 1
        class_name = tmp['modele'].unique()[0]
        df.loc[tmp.index,'target'] = int(i)
        idx_to_class.update({i:class_name})
        i+=1
        print('Count %s images for the modele: %s'%(len(tmp.index),class_name))

    with open(os.path.join(args.dir,'idx_to_class.json'), 'w') as outfile:
        json.dump(idx_to_class,outfile)

    return df

def write_df(args,df):

    df['img_path'] = df['path'] +'/' + df['img_name']
    #df.rename(columns={'_rank':'target'},inplace=True)
    cols = ['img_path','target','x1','y1','x2','y2','score']

    df[cols].head(int(df.shape[0]*(2/3.))).to_csv(os.path.join(args.dir,'train.csv'), index=False)
    df[cols].tail(int(df.shape[0]*(1/3.))).to_csv(os.path.join(args.dir,'val.csv'), index=False)

    # create mapping


def test_filter():

    # Choose yout filter
    filt_dict = dict(modele=['CLIO','MEGANE'],
        sampling=0.1,
        radar=['ETF'],
        sens=['ELOI'],
        columns=columns+['TYPEEQUIP_Libelle'],
        limit=10)


    df = filter(**filt_dict)
    assert df.shape == (filt_dict['limit'],len(filt_dict['columns'])), '{} not match with query'.format(df)
if __name__ == '__main__':
    main()
"""
python filter.py --sampling 0.1  --modele CLIO 206 --radar ETF --sens ELOI RAPP -l 10 /model/test/
"""
