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
 * The persistent class for the ASS_BP_ACCESSO database table.
 *
 */
@Entity
@Table(name="PREFERITI")
@NamedQuery(name="Preferiti.findAll", query="SELECT a FROM Preferiti a")
public class Preferiti implements Serializable {
	private static final long serialVersionUID = 1L;

	@EmbeddedId
	private PreferitiPK id;

    @Column(name="DESCRIZIONE")
    private String descrizione;

    @Transient
    private String cdNodo;

	@Temporal(TemporalType.DATE)
	private Date dacr;

	@Temporal(TemporalType.DATE)
	private Date duva;

	@Column(name="PG_VER_REC")
	private BigDecimal pgVerRec;

	private String utcr;

	private String utuv;


	public Preferiti() {
	}

	public PreferitiPK getId() {
		return this.id;
	}

	public void setId(PreferitiPK id) {
		this.id = id;
	}

    public String getDescrizione() {
        return descrizione;
    }

    public void setDescrizione(String descrizione) {
        this.descrizione = descrizione;
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

    public String getCdNodo() {
        return cdNodo;
    }

    public void setCdNodo(String cdNodo) {
        this.cdNodo = cdNodo;
    }

    @Override
    public String toString() {
        return "Preferiti{" +
            "id=" + id +
            ", descrizione='" + descrizione + '\'' +
            ", cdNodo='" + cdNodo + '\'' +
            ", dacr=" + dacr +
            ", duva=" + duva +
            ", pgVerRec=" + pgVerRec +
            ", utcr='" + utcr + '\'' +
            ", utuv='" + utuv + '\'' +
            '}';
    }
}
