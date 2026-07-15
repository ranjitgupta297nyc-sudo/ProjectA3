using System;
using System.Data.SqlClient;
using Login_Agent_578.Config;

namespace Login_Agent_578
{
    internal class SqlClient
    {
        private gConfig g_Config;

        internal SqlClient()
        {
            g_Config = gConfig.getInstance();
        }

        internal AccountInfo getAccountInfo(string id)
        {
            AccountInfo info = new AccountInfo();

            const string query = @"
        SELECT
            RTRIM(c_id),
            RTRIM(c_headera),
            RTRIM(c_status),
            d_udate
        FROM dbo.account
        WHERE RTRIM(c_id) = @id;";

            using (SqlConnection conn = new SqlConnection(g_Config.SqlConn))
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                cmd.Parameters.Add("@id", System.Data.SqlDbType.VarChar, 20)
                      .Value = id.Trim();

                try
                {
                    conn.Open();

                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                        {
                            info.id = rdr.IsDBNull(0)
                                ? string.Empty
                                : rdr.GetValue(0).ToString().Trim();

                            info.pwd = rdr.IsDBNull(1)
                                ? string.Empty
                                : rdr.GetValue(1).ToString().Trim();

                            info.status = rdr.IsDBNull(2)
                                ? string.Empty
                                : rdr.GetValue(2).ToString().Trim();

                            // EXPIRATION=0, so a missing date should not break login.
                            info.expDate = rdr.IsDBNull(3)
                                ? DateTime.MaxValue
                                : Convert.ToDateTime(rdr.GetValue(3));
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Windows.Forms.MessageBox.Show(
                        ex.ToString(),
                        "LoginAgent SQL Error",
                        System.Windows.Forms.MessageBoxButtons.OK,
                        System.Windows.Forms.MessageBoxIcon.Error
                    );
                }
            }

            return info;
        }

        internal DateTime getExpireDate(string id)
        {
            DateTime date = DateTime.Now.AddMinutes(3);
            string query = string.Format(g_Config.QueryString[1], id);

            using (SqlConnection conn = new SqlConnection(g_Config.SqlConn))
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                try
                {
                    conn.Open();
                    //날짜가 null일경우 현재 시각 리턴
                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                            date = Convert.ToDateTime(rdr[0].ToString().Trim());
                    }
                }
                catch { }
            }
            return date;
        }

        internal bool isConnectable()
        {
            bool isConn = false;
            string query = "select getdate()";

            using (SqlConnection conn = new SqlConnection(g_Config.SqlConn))
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                try
                {
                    conn.Open();
                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                            isConn = true;
                    }
                }
                catch { }
            }
            return isConn;
        }

        internal bool isExistsTable(string table)
        {
            bool isExists = false;
            string query = string.Format("select count(*) from INFORMATION_SCHEMA.TABLES where TABLE_NAME = '{0}'", table);

            using (SqlConnection conn = new SqlConnection(g_Config.SqlConn))
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                try
                {
                    conn.Open();
                    object countValue = cmd.ExecuteScalar();
                    if (0 < (int)countValue)
                        isExists = true;
                }
                catch { }
            }
            return isExists;
        }

        internal bool isExistsColumn(string column, string table)
        {
            bool isExists = false;
            string query = string.Format("select count(*) from INFORMATION_SCHEMA.COLUMNS where COLUMN_NAME = '{0}' and TABLE_NAME = '{1}'", column, table);

            using (SqlConnection conn = new SqlConnection(g_Config.SqlConn))
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                try
                {
                    conn.Open();
                    object countValue = cmd.ExecuteScalar();
                    if (0 < (int)countValue)
                        isExists = true;
                }
                catch { }
            }
            return isExists;
        }
    }
}
