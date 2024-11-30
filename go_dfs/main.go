package main

import (
	"context"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"os"
	"strings"
)

// DFS traverses the graph recursively and collects all paths
func DFS(startNode string, driver neo4j.DriverWithContext, visited map[string]bool, path string, paths *[]string) {
	query := `MATCH (a {name: $name})-[b]->(c) 
			 WHERE not type(b) in ['Read_All_Properties', 'List_Contents', 'Key_Read', 'Read_Permissions', 'RemoteInto']
			 AND not c.name IN ["Remote Management Users", "Remote Desktop Users"]
			 RETURN collect({endNode: c.name, relationship: type(b), endNodeType: c.t}) AS d`
	visited[startNode] = true
	params := map[string]interface{}{"name": startNode}
	ctx := context.Background()
	result, err := neo4j.ExecuteQuery(ctx, driver, query, params, neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase(""))
	if err != nil {
		panic(err)
	}
	records := result.Records
	for _, record := range records {
		d, ok := record.AsMap()["d"].([]interface{})
		if !ok {
			fmt.Println("Failed to cast 'd' to []interface{}")
			continue
		}

		// Check if there are no relationships (empty array `d`)
		if len(d) == 0 {
			// If no relationships, we are at a group with no outgoing relationships, backtrack.
			*paths = append(*paths, path) // Add the path for this group
			return
		}

		// Otherwise, continue traversing the graph
		for _, entry := range d {
			entryMap, ok := entry.(map[string]interface{})
			if !ok {
				fmt.Println("Failed to cast entry to map[string]interface{}")
				continue
			}
			endNode, _ := entryMap["endNode"].(string)
			rel, _ := entryMap["relationship"].(string)
			endNodeType, _ := entryMap["endNodeType"].(string)

			// Build the new path
			var newPath string
			if path == "" {
				newPath = fmt.Sprintf("%s", startNode)
			} else {
				newPath = path
			}
			newPath = fmt.Sprintf("%s - %s -> %s {type: %s}", newPath, rel, endNode, endNodeType)

			// Add the path if it's complete, else continue traversing
			if !visited[endNode] {
				DFS(endNode, driver, visited, newPath, paths)
			} else {
				*paths = append(*paths, newPath) // Add the path once traversal ends
			}
		}
	}
}

func findMaxDashes(stringsList []string) string {
	var maxString string
	maxCount := -1

	// Iterate over each string in the list
	for _, str := range stringsList {
		// Count the number of "-" characters in the current string
		count := strings.Count(str, "->")
		// Update the result if the current string has more "-" than the previous max
		if count > maxCount {
			maxCount = count
			maxString = str
		}
	}

	return maxString
}

func main() {
	args := os.Args
	if len(args) < 2 {
		panic("You need to specify the start node!")
	}

	startNode := args[1]
	//config and initiate the driver
	dbUser := ""
	dbPassword := ""
	dbUri := "bolt://localhost:7687" // scheme://host(:port) (default port is 7687)
	driver, err := neo4j.NewDriverWithContext(dbUri, neo4j.BasicAuth(dbUser, dbPassword, ""))
	ctx := context.Background()
	defer driver.Close(ctx)

	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		panic(err)
	} else {
		fmt.Printf("Furthest node paths from: %s\n\n", startNode)
	}

	session := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: ""})
	defer session.Close(ctx)

	visited := make(map[string]bool) // make visited map
	var paths []string               // empty paths

	DFS(startNode, driver, visited, "", &paths)
	longestPath := findMaxDashes(paths) // get longest path
	fmt.Println(longestPath)
}
