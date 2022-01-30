using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BS_Checker
{
    public partial class Form1 : Form
    {
        public static void RunCheck(TextBox textBox,Label tLabel, Label fLabel)
        {
            if (Regex.IsMatch(textBox.Text, @"nothing", RegexOptions.IgnoreCase) || Regex.IsMatch(textBox.Text, @"trash", RegexOptions.IgnoreCase))
            {
                tLabel.Visible = true;
                fLabel.Visible = false;
            }
            else
            {
                fLabel.Visible = true;
                tLabel.Visible = false;
            }
        }

        public Form1()
        {
            InitializeComponent();
        }

        private void Fact_Check(object sender, EventArgs e)
        {
            RunCheck(textBox1, trueLabel, falseLabel);
        }

        private void TextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                RunCheck(textBox1, trueLabel, falseLabel);
            }
        }

        private void TextBox_TextChanged(object sender, EventArgs e)
        {
            falseLabel.Visible = false;
            trueLabel.Visible = false;
        }
    }
}
