/*
 * Copyright (C) 2019  Consiglio Nazionale delle Ricerche
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package it.cnr.rsi.domain;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Date;


/**
 * The persistent class for the UTENTE_GESTORE database table.
 *
 */
@Entity
@Table(name="UTENTE_GESTORE")
@NamedQuery(name="UtenteGestore.findAll", query="SELECT u FROM UtenteGestore u")
public class UtenteGestore implements Serializable {
	private static final long serialVersionUID = 1L;

	@EmbeddedId
	private UtenteGestorePK id;

	@Temporal(TemporalType.DATE)
	private Date dacr;

	@Temporal(TemporalType.DATE)
	private Date duva;

	@Column(name="PG_VER_REC")
	private BigDecimal pgVerRec;

	private String utcr;

	private String utuv;

	//bi-directional many-to-one association to Utente
	@ManyToOne
	@JoinColumn(name="CD_UTENTE", insertable=false, updatable=false)
	private Utente utente1;

	//bi-directional many-to-one association to Utente
	@ManyToOne
	@JoinColumn(name="CD_GESTORE", insertable=false, updatable=false)
	private Utente utente2;

	public UtenteGestore() {
	}

	public UtenteGestorePK getId() {
		return this.id;
	}

	public void setId(UtenteGestorePK id) {
		this.id = id;
	}

	public Date getDacr() {
		return this.dacr;
	}

	public void setDacr(Date dacr) {
		this.dacr = dacr;
	}

	public Date getDuva() {
		return this.duva;
	}

	public void setDuva(Date duva) {
		this.duva = duva;
	}

	public BigDecimal getPgVerRec() {
		return this.pgVerRec;
	}

	public void setPgVerRec(BigDecimal pgVerRec) {
		this.pgVerRec = pgVerRec;
	}

	public String getUtcr() {
		return this.utcr;
	}

	public void setUtcr(String utcr) {
		this.utcr = utcr;
	}

	public String getUtuv() {
		return this.utuv;
	}

	public void setUtuv(String utuv) {
		this.utuv = utuv;
	}

	public Utente getUtente1() {
		return this.utente1;
	}

	public void setUtente1(Utente utente1) {
		this.utente1 = utente1;
	}

	public Utente getUtente2() {
		return this.utente2;
	}

	public void setUtente2(Utente utente2) {
		this.utente2 = utente2;
	}

}
