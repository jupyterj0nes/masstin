# Neo4j and Cypher Resources

## Setting Up Neo4j Database

Follow these steps to create a Neo4j database and set up your user credentials:

1. **Download and Install Neo4j**
   - Go to the [Neo4j Download Page](https://neo4j.com/download/) and download the appropriate version for your operating system.
   - Install Neo4j by following the instructions provided for your platform.

2. **Create a New Database**
   - Open the Neo4j application.
   - On the initial screen, click "Create a new project" if this is your first time running Neo4j.
   - Follow the prompts to create a new database. You will be asked to enter a database name, a username, and a password. Make sure to remember these credentials as you will need them later.

3. **Configure Neo4j**
   - After creating your database, ensure that the database is running. You can check this from the Neo4j Desktop application.

## Accessing Neo4j Browser

### On Windows

1. **Open Neo4j Desktop Application**
   - Launch Neo4j Desktop from your Start menu or desktop shortcut.
   - Click on the database you created to open the database management screen.

2. **Open Neo4j Browser**
   - Click the "Open" button next to the database name.
   - This will open the Neo4j Browser in your default web browser.

### On Linux

1. **Open Your Web Browser**
   - Neo4j typically runs on port 7474. Open your preferred web browser.

2. **Access Neo4j Browser**
   - Navigate to `http://localhost:7474`.
   - This will open the Neo4j Browser where you can interact with your database.

## Configuring Neo4j Browser

**Tip:** To avoid overloading your system, disable the option to automatically expand nodes in the Neo4j Browser. This setting can be found in the Neo4j Browser settings menu.

## Applying a Custom Style

To apply a custom style to your Neo4j visualizations:

1. **Run Style command**
   - Run the following command in neo4j browser:

    ```plaintext
   :style
   node {
     diameter 110px;
     color #D9C8AE;
     border-color #9AA1AC;
     border-width 2px;
     text-color-internal #FFFFFF;
     font-size 10px;
   }
   relationship {
     color #A5ABB6;
     shaft-width 1px;
     font-size 8px;
     padding 3px;
     text-color-external #000000;
     text-color-internal #FFFFFF;
     caption type;
   }
   node.host {
     color: #D9C8AE;
     border-color: #9AA1AC;
     text-color-internal: #000000;
     defaultCaption: "<id>";
     diameter: 110px;
   }
    ```

2. **Apply the Style in Neo4j Browser**
   - **Drag and Drop Method:** Drag the `style.grass` file into the Neo4j Browser window.
   - **Command Method:** Use the following command in the Neo4j Browser:

    ```cypher
    :style load /path/to/style.grass
    ```

## Useful Queries

### 1) RDP Logins (type 10) for Non-Machine Accounts in a Specific Time Frame

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2024-07-24T19:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2024-07-26T00:00:00.000000000Z")
  AND NOT r.target_user_name ENDS WITH '$'
  AND r.logon_type='10'
RETURN h1, r, h2
ORDER BY datetime(r.time)
 ```

This query retrieves RDP logins (logon type 10) that are not machine accounts and occurred within the specified time frame.

For more information on Cypher queries, please refer to the [official Cypher documentation](https://neo4j.com/docs/cypher-manual/current/).
