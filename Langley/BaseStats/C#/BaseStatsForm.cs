using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.DirectoryServices;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BaseStats
{
    public partial class BaseStatsForm : Form
    {
        static readonly DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://RootDSE");
        readonly Object domainDistinguishedName = RootDirEntry.Properties["defaultNamingContext"].Value;

        private DataSet GetBases()
        {
            //Define OUs to search in
            DirectoryEntry AFCONUSEAST = new DirectoryEntry("LDAP://OU=AFCONUSEAST,OU=Bases," + domainDistinguishedName);
            DirectoryEntry AFCONUSWEST = new DirectoryEntry("LDAP://OU=AFCONUSWEST,OU=Bases," + domainDistinguishedName);
            DirectoryEntry AFCONUSCENTRAL = new DirectoryEntry("LDAP://OU=AFCONUSCENTRAL,OU=Bases," + domainDistinguishedName);

            //Create directory searcher
            DirectorySearcher searcher = new DirectorySearcher()
            {
                Filter = "(objectCategory=OrganizationalUnit)",
                SearchScope = SearchScope.OneLevel
            };
            searcher.PropertiesToLoad.Add("Name");
            searcher.PropertiesToLoad.Add("DistinguishedName");

            //Create DataSet and DataTable
            DataSet ds = new DataSet();
            DataTable dtBases = new DataTable("dtBases");
            dtBases.Columns.Add("Name", typeof(string));
            dtBases.Columns.Add("DistinguishedName", typeof(string));

            //Run Searcher on Each OU
            searcher.SearchRoot = AFCONUSEAST;
            using (SearchResultCollection Bases = searcher.FindAll())
            {
                foreach (SearchResult sr in Bases)
                {
                    DataRow drBases = dtBases.NewRow();
                    DirectoryEntry de = sr.GetDirectoryEntry();
                    drBases["Name"] = de.Properties["Name"].Value;
                    drBases["DistinguishedName"] = de.Properties["DistinguishedName"].Value;
                    dtBases.Rows.Add(drBases);
                }
            }

            searcher.SearchRoot = AFCONUSWEST;
            using (SearchResultCollection Bases = searcher.FindAll())
            {
                foreach (SearchResult sr in Bases)
                {
                    DataRow drBases = dtBases.NewRow();
                    DirectoryEntry de = sr.GetDirectoryEntry();
                    drBases["Name"] = de.Properties["Name"].Value;
                    drBases["DistinguishedName"] = de.Properties["DistinguishedName"].Value;
                    dtBases.Rows.Add(drBases);
                }
            }

            searcher.SearchRoot = AFCONUSCENTRAL;
            using (SearchResultCollection Bases = searcher.FindAll())
            {
                foreach (SearchResult sr in Bases)
                {
                    DataRow drBases = dtBases.NewRow();
                    DirectoryEntry de = sr.GetDirectoryEntry();
                    drBases["Name"] = de.Properties["Name"].Value;
                    drBases["DistinguishedName"] = de.Properties["DistinguishedName"].Value;
                    dtBases.Rows.Add(drBases);
                }
            }

            //Add table to DataSet
            ds.Tables.Add(dtBases);
            return ds;
        }

        private int CountObjects(string OU,string type)
        {
            DirectoryEntry BaseOU = new DirectoryEntry("LDAP://" + OU);
            DirectorySearcher Searcher = new DirectorySearcher(BaseOU)
            {
                Filter = $"(objectCategory={type})",
                PageSize = 1000

            };
            Searcher.PropertiesToLoad.Add("Name");
            using (SearchResultCollection results = Searcher.FindAll())
            {
                return results.Count;
            }
        }

        private int CountBaseServers(string BaseName)
        {
            DirectoryEntry ServerOU = new DirectoryEntry("LDAP://OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers," + domainDistinguishedName);
            DirectorySearcher Searcher = new DirectorySearcher(ServerOU)
            {
                Filter = $"(&(objectCategory=OrganizationalUnit)(Name={BaseName}))"
            };
            Searcher.PropertiesToLoad.Add("Name");
            Searcher.PropertiesToLoad.Add("DistinguishedName");
            SearchResultCollection ServerOUs = Searcher.FindAll();
            int serverCount = 0;
            foreach (SearchResult Server in ServerOUs)
            {
                serverCount += CountObjects(Server.Properties["DistinguishedName"][0].ToString(),"Computer");
            }
            return serverCount;
        }

        public BaseStatsForm()
        {
            InitializeComponent();
        }

        private void Form_Load(object sender, EventArgs e)
        {
            dataGridView1.AutoGenerateColumns = true;
            dataGridView1.DataSource = GetBases();
            dataGridView1.DataMember = "dtBases";
        }

        private void SelectBases_Click(object sender, EventArgs e)
        {
            Cursor = Cursors.WaitCursor;
            DataGridViewSelectedRowCollection selectedBases = dataGridView1.SelectedRows;
            if(selectedBases.Count > 1)
            {
                int totalusercount = 0;
                int totalcomputercount = 0;
                int totalservercount = 0;
                string message = null;
                
                for (int i = 0; i < selectedBases.Count; i++)
                {
                    string BaseName = selectedBases[i].Cells[0].Value.ToString();
                    string BaseDN = selectedBases[i].Cells[1].Value.ToString();
                    int usercount = CountObjects(BaseDN,"User");
                    int computercount = CountObjects(BaseDN,"Computer");
                    int servercount = CountBaseServers(BaseName);
                    totalusercount += usercount;
                    totalcomputercount += computercount;
                    totalservercount += servercount;

                    message += $"{ BaseName }{Environment.NewLine}{ usercount} User(s){Environment.NewLine}{computercount} Computer(s){Environment.NewLine}{servercount} Servers(s){Environment.NewLine}{Environment.NewLine}";

                }
                message += $"Total{Environment.NewLine}{totalusercount} User(s){Environment.NewLine}{totalcomputercount} Computer(s){Environment.NewLine}{totalservercount} Server(s)";

                MessageBox.Show(message,"Multi-Base Results");
            }
            else
            {
                string BaseName = selectedBases[0].Cells[0].Value.ToString();
                string BaseDN = selectedBases[0].Cells[1].Value.ToString();
                int usercount = CountObjects(BaseDN, "User");
                int computercount = CountObjects(BaseDN, "Computer");
                int servercount = CountBaseServers(BaseName);

                string message = $"{ BaseName }{Environment.NewLine}{Environment.NewLine}{ usercount} User(s){Environment.NewLine}{computercount} Computer(s){Environment.NewLine}{servercount} Servers(s)";

                MessageBox.Show(message,"Single Base Results");
            }
            Cursor = Cursors.Default;
        }
    }
}
