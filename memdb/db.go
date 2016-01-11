package leveldb

import (
	"fmt"
)

type DB struct {
	db map[string][]byte
}

func NewDB() *DB {
	database := &DB{db: make(map[string][]byte)}
	return database
}

func (db *DB) Get(key []byte) []byte {
	return db.db[string(key)]
}

func (db *DB) Set(key []byte, value []byte) {
	db.db[string(key)] = value
}

func (db *DB) SetSync(key []byte, value []byte) {
	db.db[string(key)] = value
}

func (db *DB) Delete(key []byte) {
	delete(db.db, string(key))
}

func (db *DB) DeleteSync(key []byte) {
	delete(db.db, string(key))
}

func (db *DB) Close() {
	db = nil
}

func (db *DB) Print() {
	for key, value := range db.db {
		fmt.Printf("[%s]:\t[%v]\n", []byte(key), string(value))
	}
}
